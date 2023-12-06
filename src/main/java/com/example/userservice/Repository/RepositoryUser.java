package com.example.userservice.Repository;

import com.example.userservice.User.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RepositoryUser extends JpaRepository<User,Long> {
    Optional<User> findByUsername(String name);
}
