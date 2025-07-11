package com.ItRoad.signin_service.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${jwt.secret:myVerySecureSecretKeyThatIsAtLeast32CharactersLongForHS256Algorithm}")
    private String jwtSecret;

    @Value("${jwt.expiration:86400}")
    private int jwtExpirationMs;

    private SecretKey getSigningKey() {
        logger.debug("Creating signing key with secret length: {}", jwtSecret.length());
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateJwtToken(String username, String role) {
        logger.debug("Generating JWT token for username: {}, role: {}", username, role);

        try {
            String token = Jwts.builder()
                    .subject(username)
                    .claim("role", role)
                    .issuedAt(new Date())
                    .expiration(new Date((new Date()).getTime() + jwtExpirationMs * 1000L))
                    .signWith(getSigningKey(), Jwts.SIG.HS256)
                    .compact();

            logger.debug("JWT token generated successfully");
            return token;
        } catch (Exception e) {
            logger.error("Error generating JWT token: {}", e.getMessage());
            throw e;
        }
    }

    public String getUsernameFromJwtToken(String token) {
        logger.debug("Extracting username from token");
        try {
            String username = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();

            logger.debug("Username extracted: {}", username);
            return username;
        } catch (Exception e) {
            logger.error("Error extracting username: {}", e.getMessage());
            throw e;
        }
    }

    public String getRoleFromJwtToken(String token) {
        logger.debug("Extracting role from token");
        try {
            String role = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .get("role", String.class);

            logger.debug("Role extracted: {}", role);
            return role;
        } catch (Exception e) {
            logger.error("Error extracting role: {}", e.getMessage());
            throw e;
        }
    }

    public boolean validateJwtToken(String authToken) {
        logger.debug("Validating JWT token");
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(authToken);

            logger.debug("Token validation successful");
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("JWT token validation error: {}", e.getMessage());
        }
        return false;
    }
}