package com.ItRoad.signin_service.dto;


import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
public class LoginRequestDto {
    @NotBlank(message = "the username is required")
    private String username;

    @NotBlank(message = "the password is required")
    private String password;
}