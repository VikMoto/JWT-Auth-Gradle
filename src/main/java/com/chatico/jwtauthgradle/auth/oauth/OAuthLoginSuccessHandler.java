package com.chatico.jwtauthgradle.auth.oauth;

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


	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
										Authentication authentication) throws ServletException, IOException {

		response.sendRedirect("/api/v1/auth/oAuthAuthenticate");
//		super.onAuthenticationSuccess(request, response, authentication);
	}

}
