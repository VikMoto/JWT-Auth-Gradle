package com.chatico.jwtauthgradle.config;//package com.chatico.loginreggradle.config;
//
//
//import com.chatico.loginreggradle.config.CustomAuthenticationProvider;
//import com.chatico.loginreggradle.userchat.UserDetailsServiceImpl;
//import lombok.AllArgsConstructor;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//@AllArgsConstructor
//@EnableWebSecurity
//public class WebSecurityConfig  {
//
//    private final CustomAuthenticationProvider customAuthenticationProvider;
//    private final UserDetailsServiceImpl userChatDetailsService;
//    private final BCryptPasswordEncoder bCryptPasswordEncoder;
//
//    @Bean
//    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws  Exception {
//        httpSecurity
//                .csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests((authz) -> authz
//                        .requestMatchers("/api/v*/registration/**").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .formLogin(Customizer.withDefaults());
//
//        return httpSecurity.build();
//    }
//
//    @Autowired
//    public void injectCustomAuthProvider(AuthenticationManagerBuilder auth) {
//        auth.authenticationProvider(customAuthenticationProvider);
//    }
//
//
////    @Bean
////    public DaoAuthenticationProvider daoAuthenticationProvider() {
////        DaoAuthenticationProvider provider =
////                new DaoAuthenticationProvider();
////        provider.setPasswordEncoder(bCryptPasswordEncoder);
////        provider.setUserDetailsService(userChatDetailsService);
////        return provider;
////    }
//}
