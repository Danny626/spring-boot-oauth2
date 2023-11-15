package com.example.authorizationserver.dto.request;

import java.util.List;

public record CreateAppUserRequest(
    String username,
    String password,
    List<String> roles
) {}
