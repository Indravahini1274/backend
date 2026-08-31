package com.vasanth.shoppingcart.loginOrRegister.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.vasanth.shoppingcart.loginOrRegister.dto.AuthenticationRequest;
import com.vasanth.shoppingcart.loginOrRegister.dto.AuthenticationResponse;
import com.vasanth.shoppingcart.loginOrRegister.dto.RegisterRequest;
import com.vasanth.shoppingcart.loginOrRegister.entity.Role;
import com.vasanth.shoppingcart.loginOrRegister.entity.User;
import com.vasanth.shoppingcart.loginOrRegister.repository.UserRepository;
import com.vasanth.shoppingcart.security.JwtService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public String register(RegisterRequest request) {
        // 1. Create a new User object from the incoming request data
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // Hash the password!
                .role(Role.USER) // Assign default role
                .build();
        
        // 2. Save the user to the PostgreSQL database
        repository.save(user);
        
        // 3. Return a success message instead of generating a JWT token
        return "User registered successfully";
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // 1. Verify the email and password against the database
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        
        // 2. If we reach this line, the credentials are correct. Fetch the user.
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow(); // Throws exception if user doesn't exist
                
        // 3. Generate a new JWT token
        var jwtToken = jwtService.generateToken(user);
        
        // 4. Return the token mapped in our Response DTO
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}