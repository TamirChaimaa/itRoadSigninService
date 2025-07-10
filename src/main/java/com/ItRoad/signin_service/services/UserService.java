package com.ItRoad.signin_service.services;
import com.ItRoad.signin_service.dto.JwtResponseDto;
import com.ItRoad.signin_service.dto.LoginRequestDto;
import com.ItRoad.signin_service.models.User;
import com.ItRoad.signin_service.repository.UserRepository;
import com.ItRoad.signin_service.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public JwtResponseDto authenticateUser(LoginRequestDto loginRequest) {
        // Verify if the user exits
        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Verify the password
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new RuntimeException("Password incorrecte");
        }

        // Générer le token JWT
        String token = jwtUtil.generateJwtToken(user.getUsername(), user.getRole());

        return new JwtResponseDto(
                token,
                user.getId(),
                user.getUsername(),
                user.getRole(),
                "Login completed successfully"
        );
    }

    public  User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User Not Found"));
    }
}
