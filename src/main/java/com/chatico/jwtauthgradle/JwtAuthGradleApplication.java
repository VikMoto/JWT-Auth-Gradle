package com.chatico.jwtauthgradle;

import com.chatico.jwtauthgradle.auth.AuthenticationService;
import com.chatico.jwtauthgradle.auth.RegistrationRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.chatico.jwtauthgradle.userchat.Role.ADMIN;
import static com.chatico.jwtauthgradle.userchat.Role.MANAGER;

@SpringBootApplication
public class JwtAuthGradleApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtAuthGradleApplication.class, args);
    }

}
