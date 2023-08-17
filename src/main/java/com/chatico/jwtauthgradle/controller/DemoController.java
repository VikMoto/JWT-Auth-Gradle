package com.chatico.jwtauthgradle.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/demo-controller")
public class DemoController {
    @GetMapping
    public ResponseEntity<String> sayHello(HttpServletRequest request
                                           ) throws IOException {

        // Read the JSON response from the request
        BufferedReader reader = request.getReader();
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        String jsonResponse = sb.toString();

        System.out.println("jsonResponse = " + jsonResponse);

        // Combine the message
        String message = jsonResponse + " Hello from demo controller";

        return ResponseEntity.ok(message);
    }
}
