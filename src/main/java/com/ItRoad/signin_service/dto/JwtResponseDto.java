package com.ItRoad.signin_service.dto;

import lombok.Data;
import lombok.AllArgsConstructor;

@Data
@AllArgsConstructor
public class JwtResponseDto {
    private String token;
    private String type = "Bearer";
    private Long id;
    private String username;
    private String role;
    private String message;

    public JwtResponseDto(String token, Long id, String username, String role, String message) {
        this.token = token;
        this.id = id;
        this.username = username;
        this.role = role;
        this.message = message;
    }
}
