package com.chatico.jwtauthgradle.email;

public interface EmailSender {
    void send(String to, String email);
}
