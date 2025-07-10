package com.ItRoad.signin_service.controllers;

import com.ItRoad.signin_service.dto.JwtResponseDto;
import com.ItRoad.signin_service.dto.LoginRequestDto;
import com.ItRoad.signin_service.models.User;
import com.ItRoad.signin_service.services.UserService;
import com.ItRoad.signin_service.utils.JwtUtil;
import lombok.Data;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*") // Allow cross-origin requests from any domain
public class SignInController {

    @Autowired
    private UserService userService;
    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Endpoint to handle user login.
     * Accepts login credentials and returns a JWT token upon successful authentication.
     */
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequestDto loginRequest) {
        try {
            JwtResponseDto response = userService.authenticateUser(loginRequest);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse(e.getMessage()));
        }
    }

    /**
     * Endpoint to validate a JWT token.
     * Extracts the token from the   Authorization header and checks its validity.
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String token) {
        try {
            // Check if the Authorization header is present and properly formatted
            if (token == null || !token.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ErrorResponse("Missing or invalid token format"));
            }

            // Extract the actual JWT token by removing the "Bearer " prefix
            String jwtToken = token.substring(7);

            // Validate the token using JwtUtil
            if (!jwtUtil.validateJwtToken(jwtToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ErrorResponse("Invalid or expired token"));
            }

            // Extract username and role from the JWT token
            String username = jwtUtil.getUsernameFromJwtToken(jwtToken);
            String role = jwtUtil.getRoleFromJwtToken(jwtToken);

            // Check if the user still exists in the database
            User user = userService.findByUsername(username);
            // Build the response with user information
            TokenValidationResponse response = new TokenValidationResponse(
                    "Valid token",
                    user.getId(),
                    user.getUsername(),
                    user.getRole(),
                    true
            );

            // Return success response
            return ResponseEntity.ok(response);

        } catch (RuntimeException e) {
            // Handle case when user is not found or other runtime issues
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("User not found: " + e.getMessage()));
        } catch (Exception e) {
            // Handle general errors during token validation
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Error during token validation: " + e.getMessage()));
        }
    }


    /**
     * Inner class for returning error messages in API responses.
     */
    @Getter
    public static class ErrorResponse {
        private String message;

        public ErrorResponse(String message) {
            this.message = message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }

    /**
     * New class for complete token validation response
     */

    @Data
    public static class TokenValidationResponse {
        private String message;
        private Long userId;
        private String username;
        private String role;
        private boolean valid;

        public TokenValidationResponse(String message, Long userId, String username, String role, boolean valid) {
            this.message = message;
            this.userId = userId;
            this.username = username;
            this.role = role;
            this.valid = valid;
        }

        /**
         * Inner class for returning success messages when validating tokens.
         */
        @Getter
        public static class ValidationResponse {
            private String message;

            public ValidationResponse(String message) {
                this.message = message;
            }

            public void setMessage(String message) {
                this.message = message;
            }
        }
    }
}
