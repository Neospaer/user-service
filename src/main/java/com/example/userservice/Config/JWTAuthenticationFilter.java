package com.example.userservice.Config;

import com.example.userservice.Repository.RepositoryToken;
import com.example.userservice.Service.ServiceJWTImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    private final ServiceJWTImpl serviceJWT;
    private final UserDetailsService userDetailsService;
    private final RepositoryToken repositoryToken;
    public JWTAuthenticationFilter(ServiceJWTImpl serviceJWT, UserDetailsService userDetailsService, RepositoryToken repositoryToken){
        this.serviceJWT = serviceJWT;
        this.userDetailsService = userDetailsService;
        this.repositoryToken = repositoryToken;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String JWT;
        final String userName;
        if(authHeader == null  || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }
        JWT = authHeader.substring(7);
        userName = serviceJWT.extractUserName(JWT);
        if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userName);
            var isTokenValid = repositoryToken.findByToken(JWT)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);
            if(serviceJWT.isTokenValid(JWT, userDetails) && isTokenValid){
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
            filterChain.doFilter(request, response);
        }
    }

}
