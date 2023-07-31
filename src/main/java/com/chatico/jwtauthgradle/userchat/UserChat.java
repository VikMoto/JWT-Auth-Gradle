package com.chatico.jwtauthgradle.userchat;



import com.chatico.jwtauthgradle.token.Token;
import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;


@Entity
@Table(name = "userchat")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
//@Validated
public class UserChat implements UserDetails {
//public class UserChat {


    @SequenceGenerator(
            name = "userchat_sequence",
            sequenceName = "userchat_sequence",
            allocationSize = 1
    )

    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "userchat_sequence"
    )
    @Id
    private Long id;

    private String firstName;
    private String lastName;
    private String username;
    private String email;
    private String password;

    private Boolean enabled = false;
    private Boolean locked = false;

   private String userPic;


    @Enumerated(EnumType.STRING)
    private Gender gender;

    @Enumerated(EnumType.STRING)
    private Provider provider;


    @Enumerated(EnumType.STRING)
    private Role role;

    @OneToMany(mappedBy = "userChat")
    private List<Token> tokens;


//    @OneToMany(mappedBy = "userChat", cascade = CascadeType.ALL, orphanRemoval = true)
//    private List<Permission> permissions = new ArrayList<>();


    private String locale;

    private LocalDate birthday;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime lastVisit;

    private Boolean isAccountNonExpired;
    private Boolean isAccountNonLocked;
    private Boolean isCredentialsNonExpired;
    private Boolean isEnabled;

//    @OneToMany(
//            mappedBy = "userChat",
//            orphanRemoval = true,
//            cascade = CascadeType.ALL
//    )
////    @JoinColumn(name = "group_chat_id")
//    private Set<UserContacts> contacts = new TreeSet<>();
////
    public enum Gender{
        MALE, FEMALE
    }

    public UserChat(String firstName,
                   String lastName,
                   String email,
                   String password,
                   Role role) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.role = role;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserChat userChat = (UserChat) o;
        return this.id != null && Objects.equals(id, userChat.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        SimpleGrantedAuthority authority =
                new SimpleGrantedAuthority(role.name());
        return Collections.singletonList(authority);
    }

    public boolean isAccountNonExpired() {
        return isAccountNonExpired;
    }

    public boolean isAccountNonLocked() {
        return isAccountNonLocked;
    }

    public boolean isCredentialsNonExpired() {
        return isCredentialsNonExpired;
    }

    public boolean isEnabled() {
        return enabled;
    }
}
