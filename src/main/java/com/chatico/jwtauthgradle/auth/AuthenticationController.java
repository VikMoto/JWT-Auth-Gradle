package com.chatico.jwtauthgradle.auth;

import com.chatico.jwtauthgradle.auth.oauth.CustomOAuth2User;
import com.chatico.jwtauthgradle.service.UserChatService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping(path = "/api/v1/auth")
public class AuthenticationController {


    private final AuthenticationService authenticationService;
    private final UserChatService userChatService;


    public AuthenticationController(@Lazy AuthenticationService authenticationService, UserChatService userChatService) {
        this.authenticationService = authenticationService;
        this.userChatService = userChatService;
    }


    @PostMapping("/registration")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegistrationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @GetMapping("/oAuthAuthenticate")
    public ResponseEntity<AuthenticationResponse> oAuthAuthenticate(
            HttpServletRequest request, HttpServletResponse response,
           Authentication authentication) throws ServletException, IOException
     {
         CustomOAuth2User oauth2User = (CustomOAuth2User) authentication.getPrincipal();
         String oauth2ClientName = oauth2User.getOauth2ClientName();
         String username = oauth2User.getEmail();

         userChatService.updateAuthenticationType(username, oauth2ClientName);
         System.out.println("username = " + username);
         AuthenticationResponse authenticationResponse = authenticationService.authenticateOAuth(username);
        return ResponseEntity.ok(authenticationResponse);
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        authenticationService.refreshToken(request, response);
    }

}
