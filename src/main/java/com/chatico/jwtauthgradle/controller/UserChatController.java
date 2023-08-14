package com.chatico.jwtauthgradle.controller;



import com.chatico.jwtauthgradle.auth.RegistrationRequest;
import com.chatico.jwtauthgradle.repository.UserChatRepository;
import com.chatico.jwtauthgradle.userchat.Role;
import com.chatico.jwtauthgradle.userchat.UserChat;
import com.chatico.jwtauthgradle.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;



@Log4j2
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserChatController {
    private final static int DELAY = 100;
    private final UserChatRepository userChatRepository;
    private final UserDetailsServiceImpl userchatService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/list")
    public List<UserChat> list() {
        return new ArrayList<>(userChatRepository.findAll());
    }

    @PostMapping()
    public UserChat createUserChat(@RequestBody RegistrationRequest userchatRegDto) {
        UserChat userChat = UserChat.builder()
                .username(userchatRegDto.getEmail())
                .email(userchatRegDto.getEmail())
                .password("{bcrypt}" + bCryptPasswordEncoder.encode(userchatRegDto.getPassword()))
                .locale(null)
                .role(Role.USER)
                .lastVisit(LocalDateTime.now())
                .build();
        // Assuming you have a list of role names in the UserchatRegDto, you can add them to the userChat entity
        UserChat userChatSaved = userChatRepository.save(userChat);

        log.info("userChatSaved {}", userChatSaved);


        log.info("userChatSaved2 {}", userChatSaved);
        return userChatRepository.findById(userChatSaved.getId()).get();
    }

//    @GetMapping("/{id}")
//    public UserChatDto getUserChatWithMessages(@PathVariable("id")  Long id) throws InterruptedException {
//        UserChat userChat = userChatRepository.findById(id).orElseThrow();
//        UserChatDto userChatDto = UserChatDto.builder()
//                .id(userChat.getId())
//                .name(userChat.getUsername())
//                .build();
//        log.info("waiting {}ms", DELAY);
////        Thread.sleep(DELAY += 50);
//        log.info("responding with error");
//        return userChatDto;
////        throw new RuntimeException("Unexpected error");
//    }
}
