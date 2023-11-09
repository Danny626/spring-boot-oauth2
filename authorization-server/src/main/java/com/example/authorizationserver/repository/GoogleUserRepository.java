package com.example.authorizationserver.repository;

import com.example.authorizationserver.entity.GoogleUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface GoogleUserRepository extends JpaRepository<GoogleUser, Integer> {
    Optional<GoogleUser> findByEmail(String email);
}
