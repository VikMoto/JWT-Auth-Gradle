package com.chatico.jwtauthgradle.service;



import com.chatico.jwtauthgradle.repository.UserChatRepository;
import com.chatico.jwtauthgradle.token.ConfirmationToken;
import com.chatico.jwtauthgradle.token.ConfirmationTokenService;
import com.chatico.jwtauthgradle.userchat.UserChat;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

import static com.chatico.jwtauthgradle.userchat.Constants.ADMIN_PASSWORD;
import static com.chatico.jwtauthgradle.userchat.Constants.ADMIN_USERNAME;


@Slf4j
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
	private final UserChatRepository userChatRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final ConfirmationTokenService confirmationTokenService;

	private static final String USER_NOT_FOUND = "Could not find user with email %s ";

	@Value(value = "${" + ADMIN_USERNAME + "}")
	private String username;

	@Value(value = "${" + ADMIN_PASSWORD + "}")
	private String password;


	@Override
	public UserDetails loadUserByUsername(String email)
			throws UsernameNotFoundException {
		
		return userChatRepository.findByEmail(email)
				.orElseThrow(() ->
						new UsernameNotFoundException(
								String.format(USER_NOT_FOUND, email)));
	}

	public String signUpUser(UserChat userChat) {
		boolean userExists = userChatRepository
				.findByEmail(userChat.getEmail())
				.isPresent();

		if (userExists) {
			// TODO check of attributes are the same and
			// TODO if email not confirmed send confirmation email.

			return "Email already taken";
		}

		String encodedPassword = bCryptPasswordEncoder
				.encode(userChat.getPassword());

		userChat.setPassword(encodedPassword);

		userChatRepository.save(userChat);

		String token = UUID.randomUUID().toString();

		ConfirmationToken confirmationToken = new ConfirmationToken(
				token,
				LocalDateTime.now(),
				LocalDateTime.now().plusMinutes(15),
				userChat
		);

		confirmationTokenService.saveConfirmationToken(
				confirmationToken);

//        TODO: SEND EMAIL

		return token;
	}

	public int enableUserChat(String email) {
		return userChatRepository.enableUserChat(email);
	}
}
