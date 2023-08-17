package com.chatico.jwtauthgradle.auth.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;




import com.chatico.jwtauthgradle.auth.AuthenticationResponse;
import com.chatico.jwtauthgradle.auth.AuthenticationService;
import com.chatico.jwtauthgradle.service.UserChatService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuthLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {


	 private final UserChatService userChatService;
	 private final AuthenticationService authenticationService;
	 private final BCryptPasswordEncoder bCryptPasswordEncoder;

	public OAuthLoginSuccessHandler(UserChatService userChatService,
									AuthenticationService authenticationService,
									AuthenticationService authenticationService1, BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.userChatService = userChatService;
		this.authenticationService = authenticationService1;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}




	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
										Authentication authentication) throws ServletException, IOException {
//		CustomOAuth2User oauth2User = (CustomOAuth2User) authentication.getPrincipal();
//		String oauth2ClientName = oauth2User.getOauth2ClientName();
//		String username = oauth2User.getEmail();
//
//		userChatService.updateAuthenticationType(username, oauth2ClientName);
//		System.out.println("username = " + username);
//		AuthenticationResponse authenticationResponse = authenticationService.authenticateOAuth(username);
//		// Convert the AuthenticationResponse object to a JSON string
//		ObjectMapper objectMapper = new ObjectMapper();
//		String jsonResponse = objectMapper.writeValueAsString(authenticationResponse);
//
//		System.out.println("jsonResponse = " + jsonResponse);
//
//		// Set headers and write JSON response
//		response.setContentType("application/json");
//		response.setCharacterEncoding("UTF-8");
//		response.getWriter().write(jsonResponse);

//		System.out.println("send redirect +  /api/v1/demo-controller");
		response.sendRedirect("/api/v1/auth/oAuthAuthenticate");
//		super.onAuthenticationSuccess(request, response, authentication);
	}

}
