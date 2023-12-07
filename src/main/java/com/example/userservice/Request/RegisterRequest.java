package com.example.userservice.Request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    @NotBlank
    private String name;

    @NotBlank
    private String username;

    @NotBlank
    private String password;

    @NotBlank
    private String confirmPassword;
}