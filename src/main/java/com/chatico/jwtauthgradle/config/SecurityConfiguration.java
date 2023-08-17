package com.chatico.jwtauthgradle.config;

import com.chatico.jwtauthgradle.auth.oauth.CustomOAuth2UserService;
import com.chatico.jwtauthgradle.auth.oauth.OAuthLoginSuccessHandler;
import com.chatico.jwtauthgradle.repository.UserChatRepository;
import com.chatico.jwtauthgradle.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.chatico.jwtauthgradle.userchat.Permission.*;
import static com.chatico.jwtauthgradle.userchat.Role.ADMIN;
import static com.chatico.jwtauthgradle.userchat.Role.MANAGER;
import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity

@EnableMethodSecurity
public class SecurityConfiguration {

  private final JwtAuthenticationFilter jwtAuthFilter;
  private final CustomAuthenticationProvider authenticationProvider;
    private final UserChatRepository userChatRepository;
    private final PasswordEncoder passwordEncoder;
//  private final LogoutHandler logoutHandler;
  private final OAuthLoginSuccessHandler oauthLoginSuccessHandler;
  private final CustomOAuth2UserService oauth2UserService;
  private final UserDetailsServiceImpl userDetailService;

    public SecurityConfiguration(JwtAuthenticationFilter jwtAuthFilter,
                                 CustomAuthenticationProvider authenticationProvider,
                                 UserChatRepository userChatRepository,
                                 PasswordEncoder passwordEncoder,
                                 @Lazy OAuthLoginSuccessHandler oauthLoginSuccessHandler,
                                 CustomOAuth2UserService oauth2UserService,
                                 UserDetailsServiceImpl userDetailService) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.authenticationProvider = authenticationProvider;
        this.userChatRepository = userChatRepository;
        this.passwordEncoder = passwordEncoder;
        this.oauthLoginSuccessHandler = oauthLoginSuccessHandler;
        this.oauth2UserService = oauth2UserService;
        this.userDetailService = userDetailService;
    }

    @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable())
            .authorizeHttpRequests((authorizeHttpRequests) ->
                    authorizeHttpRequests
                            .requestMatchers(
                "/api/v1/auth/**",
                "/api/v*/auth/registration/**",
                "/v2/api-docs",
                "/v3/api-docs",
                "/v3/api-docs/**",
                "/swagger-resources",
                "/swagger-resources/**",
                "/configuration/ui",
                "/configuration/security",
                "/swagger-ui/**",
                "/webjars/**",
                "/swagger-ui.html"
        )
          .permitAll()
        .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
        .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
        .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
        .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
        .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

        .anyRequest()
          .authenticated())
//        .sessionManagement((sessionManagement) ->
//                sessionManagement
//                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        )
        .authenticationProvider(authenticationProvider)
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .oauth2Login((login) -> login
                .loginPage("/login")
                .defaultSuccessUrl("/api/v1/demo-controller")
                .permitAll()
                    .userInfoEndpoint(userInfoEndpoint->
                            userInfoEndpoint.userService(oauth2UserService))
                        .successHandler(oauthLoginSuccessHandler))
//            .logout(Customizer.withDefaults())
//        .logout((logout) ->
//                logout.deleteCookies("remove")
//                        .invalidateHttpSession(false)
//                        .logoutUrl("/api/v1/auth/logout")
//                        .logoutSuccessUrl("/")
//                        .permitAll()
//        )

//        .logoutHandler(logoutHandler)
//        .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
    ;

    return http.build();
  }


    @Bean
    public AuthenticationManager customAuthenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailService);
        authProvider.setPasswordEncoder(passwordEncoder);
        authenticationManagerBuilder.authenticationProvider(authProvider);
        return authenticationManagerBuilder.build();
    }
}
