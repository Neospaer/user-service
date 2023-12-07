package com.example.userservice.Controller;

import com.example.userservice.Request.AuthenticationRequest;
import com.example.userservice.Request.RegisterRequest;
import com.example.userservice.Request.SignOutRequest;
import com.example.userservice.Responce.AuthenticationResponse;
import com.example.userservice.Service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api")
public class ControllerUser {
    private final AuthenticationService service;

    public ControllerUser(AuthenticationService service) {
        this.service = service;
    }


    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ){
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/auth")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody AuthenticationRequest request
    ){
        return ResponseEntity.ok(service.authentication(request));
    }

    @PostMapping("/refresh")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request, response);
    }
    /*@PostMapping("/signout")
    public void signout(@RequestBody @Valid SignOutRequest request) {
        tokenService.deleteByAccessToken(request.getAccessToken()
    }*/
}
