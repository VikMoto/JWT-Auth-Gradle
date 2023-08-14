package com.chatico.jwtauthgradle.repository;

import com.chatico.jwtauthgradle.auth.AuthenticationType;
import com.chatico.jwtauthgradle.userchat.UserChat;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

@Transactional
public interface UserChatRepository extends JpaRepository<UserChat, Long> {
//    @Query("select distinct u from UserChat u left join fetch u.roles where u.email=:email")
    @Query("select distinct u from UserChat u where u.email = ?1")
    UserChat findByEmailFetchRoes(String email);
    Optional<UserChat> findByEmail(String email);
    @org.springframework.transaction.annotation.Transactional
    @Modifying
    @Query("UPDATE UserChat u " +
            "SET u.enabled = TRUE WHERE u.email = ?1")
    int enableUserChat(String email);

    @Modifying
    @Query("UPDATE UserChat u SET u.authType = ?2 WHERE u.username = ?1")
    public void updateAuthenticationType(String username, AuthenticationType authType);
}
