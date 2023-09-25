package com.markos96.springbootsecurity.service;

import com.markos96.springbootsecurity.dto.AuthResponseDTO;
import com.markos96.springbootsecurity.dto.LoginDTO;
import com.markos96.springbootsecurity.dto.RegisterDTO;
import com.markos96.springbootsecurity.entity.Role;
import com.markos96.springbootsecurity.entity.User;
import com.markos96.springbootsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private UserRepository userRepository;
    private JwtService jwtService;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;

    public AuthResponseDTO login(LoginDTO loginDTO) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword()));
        UserDetails user = userRepository.findByUsername(loginDTO.getUsername()).orElseThrow();
        String token = jwtService.getToken(user);

        return AuthResponseDTO.builder()
                .token(token)
                .build();
    }

    public String register(RegisterDTO registerDTO) {
        User user = User.builder()
                .username(registerDTO.getUsername())
                .password(passwordEncoder.encode(registerDTO.getPassword()))
                .firstname(registerDTO.getFirstname())
                .lastname(registerDTO.getLastname())
                .country(registerDTO.getCountry())
                .role(Role.USER)
                .build();

        userRepository.save(user);

        return "User registred successfully";
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {this.userRepository = userRepository;}
    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder){this.passwordEncoder = passwordEncoder;}
    @Autowired
    public void setJwtService(JwtService jwtService) {this.jwtService = jwtService;}
    @Autowired
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {this.authenticationManager = authenticationManager;}
}
