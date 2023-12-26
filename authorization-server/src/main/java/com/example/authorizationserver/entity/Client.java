package com.example.authorizationserver.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class Client {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String clientId;
    private String clientSecret;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<ClientAuthenticationMethod> authenticationMethods;
    @OneToMany(mappedBy = "client", fetch = FetchType.EAGER)
    private Set<ClientRedirectUrl> redirectUris;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> postLogoutRedirectUris;
    @ManyToMany(cascade = CascadeType.PERSIST, fetch = FetchType.EAGER)
    @JoinTable(name = "client_scope_mapping",
        joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "id"),
        inverseJoinColumns = @JoinColumn(name = "scope_id", referencedColumnName = "id")
    )
    private Collection<ClientScope> scopes;
    private boolean requireProofKey;

    public static RegisteredClient toRegisteredClient(Client client) {
        RegisteredClient.Builder builder = RegisteredClient.withId(client.getClientId())
            .clientId(client.getClientId())
            .clientSecret(client.getClientSecret())
            .clientAuthenticationMethods(am -> am
                .addAll(client.getAuthenticationMethods()))
            .authorizationGrantTypes(agt -> agt
                .addAll(client.getAuthorizationGrantTypes()))
            .redirectUris(
                ru -> ru.addAll(client.getRedirectUris()
                    .stream()
                    .map(ClientRedirectUrl::getUrl)
                    .collect(Collectors.toSet())))
            .postLogoutRedirectUris(pl -> pl.addAll(client.getPostLogoutRedirectUris()))
            .scopes(sc -> sc.addAll(client.getScopes()
                .stream()
                .map(ClientScope::getScope)
                .collect(Collectors.toSet())))
            .clientIdIssuedAt(new Date().toInstant())
            .clientSettings(ClientSettings
                .builder()
                .requireProofKey(client.isRequireProofKey())
                .requireAuthorizationConsent(true)
                .build());
        return builder.build();
    }

    /*@ElementCollection(fetch = FetchType.EAGER)
    private Set<String> redirectUris;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<ClientAuthenticationMethod> authenticationMethods;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> scopes;*/


    /*public static RegisteredClient toRegisteredClient(Client client) {
        RegisteredClient.Builder builder = RegisteredClient.withId(client.getClientId())
            .clientId(client.getClientId())
            .clientSecret(client.getClientSecret())
            .clientIdIssuedAt(new Date().toInstant())
            .clientAuthenticationMethods(am -> am
                .addAll(client.getAuthenticationMethods()))
            .authorizationGrantTypes(agt -> agt
                .addAll(client.getAuthorizationGrantTypes()))
            .redirectUris(ru -> ru.addAll(client.getRedirectUris()))
            .scopes(sc -> sc.addAll(client.getScopes()))
            .clientSettings(ClientSettings
                .builder().requireProofKey(client.isRequireProofKey()).build());
        return builder.build();
    }*/
}
