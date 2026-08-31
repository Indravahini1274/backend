package com.vasanth.shoppingcart.loginOrRegister.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vasanth.shoppingcart.loginOrRegister.dto.AuthenticationRequest;
import com.vasanth.shoppingcart.loginOrRegister.dto.AuthenticationResponse;
import com.vasanth.shoppingcart.loginOrRegister.dto.RegisterRequest;
import com.vasanth.shoppingcart.loginOrRegister.service.AuthService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService service;

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody RegisterRequest request
    ) {
        // Now expects a String response from the service instead of a JWT token
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @Valid @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(service.authenticate(request));
    }
}