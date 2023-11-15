package com.example.authorizationserver.repository;

import com.example.authorizationserver.entity.ClientScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientScopeRepository extends JpaRepository<ClientScope, Integer> {
}
