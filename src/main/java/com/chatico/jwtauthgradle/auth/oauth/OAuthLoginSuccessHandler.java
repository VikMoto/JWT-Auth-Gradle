package com.chatico.jwtauthgradle.auth.oauth;




import com.chatico.jwtauthgradle.service.UserChatService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuthLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {


	 private final UserChatService userChatService;

	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	public OAuthLoginSuccessHandler(UserChatService userChatService, BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.userChatService = userChatService;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}




	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
										Authentication authentication) throws ServletException, IOException {
		CustomOAuth2User oauth2User = (CustomOAuth2User) authentication.getPrincipal();
		String oauth2ClientName = oauth2User.getOauth2ClientName();
		String username = oauth2User.getEmail();
		
		userChatService.updateAuthenticationType(username, oauth2ClientName);
		
		super.onAuthenticationSuccess(request, response, authentication);
	}

}
