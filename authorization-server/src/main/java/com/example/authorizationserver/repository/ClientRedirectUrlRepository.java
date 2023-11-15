package com.example.authorizationserver.repository;

import com.example.authorizationserver.entity.ClientRedirectUrl;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRedirectUrlRepository extends JpaRepository<ClientRedirectUrl, Integer> {
}
