package com.markos96.springbootsecurity.controller;

import com.markos96.springbootsecurity.dto.AuthResponseDTO;
import com.markos96.springbootsecurity.dto.LoginDTO;
import com.markos96.springbootsecurity.dto.RegisterDTO;
import com.markos96.springbootsecurity.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private AuthService authService;
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@RequestBody LoginDTO loginDTO){
        return ResponseEntity.ok(authService.login(loginDTO));
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterDTO registerDTO){
        return ResponseEntity.ok(authService.register(registerDTO));
    }

    @Autowired
    public void setAuthService(AuthService authService) {this.authService = authService;}
}
