package com.chatico.jwtauthgradle.service;


import com.chatico.jwtauthgradle.auth.AuthenticationType;
import com.chatico.jwtauthgradle.repository.UserChatRepository;
import com.chatico.jwtauthgradle.userchat.Role;
import com.chatico.jwtauthgradle.userchat.UserChat;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import static com.chatico.jwtauthgradle.userchat.Constants.ADMIN_PASSWORD;
import static com.chatico.jwtauthgradle.userchat.Constants.ADMIN_USERNAME;

@Slf4j
@Service
@Transactional
public class UserChatService {

    private final UserChatRepository userChatRepository;
    private final BCryptPasswordEncoder passwordEncoder;


    @Value(value = "${" + ADMIN_USERNAME + "}")
    private String username;

    @Value(value = "${" + ADMIN_PASSWORD + "}")
    private String password;

    public UserChatService(UserChatRepository userChatRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userChatRepository = userChatRepository;
        this.passwordEncoder = passwordEncoder;
    }

//    @PostConstruct
//    private void setup() {
//        log.info("started service:{} setup", UserChatService.class.getSimpleName());
//
//        UserChat userChat = userChatRepository.findByEmailFetchRoes(username);
//        System.out.println("userChat = " + userChat);
//
//        if (userChat == null) {
//            UserChat standartUserChat = UserChat.builder()
//                    .username(username)
//                    .email(username)
//                    .password(passwordEncoder.encode(password))
//                    .role(Role.ADMIN)
//                    .enabled(true)
//                    .authType(AuthenticationType.DATABASE)
//                    .build();
//            userChatRepository.save(standartUserChat);
//        }
//        log.info("service:{} setup finished", UserChatService.class.getSimpleName());
//
//    }
    public void updateAuthenticationType(String username, String oauth2ClientName) {
        UserChat userChat = userChatRepository.findByEmailFetchRoes(username);
        System.out.println("userChat = " + userChat);

        AuthenticationType authType = AuthenticationType.valueOf(oauth2ClientName.toUpperCase());
        if (userChat == null) {
            UserChat standartUserChat = UserChat.builder()
                    .username(username)
                    .email(username)
                    .password("")
                    .role(Role.USER)
                    .enabled(true)
                    .authType(authType)
                    .build();
            userChatRepository.save(standartUserChat);
        }

//    	userChatRepository.updateAuthenticationType(username, authType);
    	System.out.println("Updated user's authentication type to " + authType);
    }	
}
