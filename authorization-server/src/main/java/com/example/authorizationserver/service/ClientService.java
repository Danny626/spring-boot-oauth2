package com.example.authorizationserver.service;

import com.example.authorizationserver.dto.request.CreateClientRequest;
import com.example.authorizationserver.dto.response.MessageResponse;
import com.example.authorizationserver.entity.Client;
import com.example.authorizationserver.entity.ClientRedirectUrl;
import com.example.authorizationserver.entity.ClientScope;
import com.example.authorizationserver.repository.ClientRedirectUrlRepository;
import com.example.authorizationserver.repository.ClientRepository;
import com.example.authorizationserver.repository.ClientScopeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientService implements RegisteredClientRepository {
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final ClientRedirectUrlRepository clientRedirectUrlRepository;
    private final ClientScopeRepository clientScopeRepository;

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findByClientId(id)
            .orElseThrow(() -> new RuntimeException("Client not found"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
            .orElseThrow(() -> new RuntimeException("Client not found"));
        return Client.toRegisteredClient(client);
    }

    public MessageResponse create(CreateClientRequest request) {
        var scopes = request
            .getScopes()
            .stream()
            .map(clientScope -> new ClientScope())
            .collect(Collectors.toSet());
//        scopes.forEach(clientScopeRepository::save);

        Client client = clientFromDto(request);
        /*clientRepository.save(client);
        var client = new Client(request);*/
        client.setScopes(scopes);
        clientRepository.save(client);

        client.setRedirectUris(request.getRedirectUris().stream()
            .map(url -> new ClientRedirectUrl(url, client))
            .collect(Collectors.toSet()));
        client.getRedirectUris().forEach(clientRedirectUrlRepository::save);

        return new MessageResponse("Client " + client.getClientId() + " saved");
    }

    // private methods
    private Client clientFromDto(CreateClientRequest request) {
        return Client.builder()
            .clientId(request.getClientId())
            .clientSecret(passwordEncoder.encode(request.getClientSecret()))
            .authenticationMethods(request.getAuthenticationMethods())
            .authorizationGrantTypes(request.getAuthorizationGrantTypes())
//            .redirectUris(request.getRedirectUris())
//            .scopes(request.getScopes())
            .requireProofKey(request.isRequireProofKey())
            .build();
    }
}
