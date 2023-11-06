package com.example.authorizationserver.service;

import com.example.authorizationserver.dto.CreateAppUserDto;
import com.example.authorizationserver.dto.MessageDto;
import com.example.authorizationserver.entity.AppUser;
import com.example.authorizationserver.entity.Role;
import com.example.authorizationserver.enums.RoleName;
import com.example.authorizationserver.repository.AppUserRepository;
import com.example.authorizationserver.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppUserService {
    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public MessageDto createUser(CreateAppUserDto dto) {
        AppUser appUser = AppUser.builder()
            .username(dto.username())
            .password(passwordEncoder.encode(dto.password()))
            .build();
        Set<Role> roles = new HashSet<>();
        dto.roles().forEach(r -> {
            Role role = roleRepository.findByRole(RoleName.valueOf(r))
                .orElseThrow(() -> new RuntimeException("Role not found"));
            roles.add(role);
        });
        appUser.setRoles(roles);
        appUserRepository.save(appUser);

        return new MessageDto("user " + appUser.getUsername() + " saved");
    }
}
