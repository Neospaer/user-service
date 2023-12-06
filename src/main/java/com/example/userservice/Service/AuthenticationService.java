package com.example.userservice.Service;

import com.example.userservice.Repository.RepositoryToken;
import com.example.userservice.Repository.RepositoryUser;
import com.example.userservice.Request.AuthenticationRequest;
import com.example.userservice.Request.RequestRegister;
import com.example.userservice.Responce.AuthenticationResponse;
import com.example.userservice.User.Role;
import com.example.userservice.User.Token;
import com.example.userservice.User.TokenType;
import com.example.userservice.User.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class AuthenticationService {
    private final RepositoryUser repositoryUser;
    private final PasswordEncoder passwordEncoder;
    private final ServiceJWTImpl serviceJWT;

    private final RepositoryToken repositoryToken;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(RepositoryUser repositoryUser, PasswordEncoder passwordEncoder, ServiceJWTImpl serviceJWT, RepositoryToken repositoryToken, AuthenticationManager authenticationManager) {
        this.repositoryUser = repositoryUser;
        this.passwordEncoder = passwordEncoder;
        this.serviceJWT = serviceJWT;
        this.repositoryToken = repositoryToken;
        this.authenticationManager = authenticationManager;
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .typeToken(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        repositoryToken.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = repositoryToken.findAllValidTokensByUser(Math.toIntExact(user.getId()));
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        repositoryToken.saveAll(validUserTokens);
    }

    public AuthenticationResponse register(RequestRegister request) {
        var user = User.builder()
                .name(request.getName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repositoryUser.save(user);
        var savedUser = repositoryUser.save(user);
        var JwtToken = serviceJWT.generateToken(user);
        var refreshToken = serviceJWT.generateRefreshToken(user);
        saveUserToken(savedUser, JwtToken);
        return AuthenticationResponse
                .builder()
                .accessToken(JwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authentication(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUserName(),
                        request.getPassword()
                )
        );
        var user = repositoryUser.findByUsername(request.getUserName())
                .orElseThrow();
        var JwtToken = serviceJWT.generateToken(user);
        var refreshToken = serviceJWT.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, JwtToken);
        return AuthenticationResponse.builder()
                .accessToken(JwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userName;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userName = serviceJWT.extractUserName(refreshToken);
        if (userName != null) {
            var userDetails = this.repositoryUser.findByUsername(userName).orElseThrow();
            if (serviceJWT.isTokenValid(refreshToken, userDetails)) {
                var accessToken = serviceJWT.generateToken(userDetails);
                revokeAllUserTokens(userDetails);
                saveUserToken(userDetails, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}
