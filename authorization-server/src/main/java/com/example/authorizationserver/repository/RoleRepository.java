package com.example.authorizationserver.repository;

import com.example.authorizationserver.entity.Role;
import com.example.authorizationserver.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByRole(RoleName roleName);
}
