package com.example.authorize.oauth2.config;

import com.example.authorize.oauth2.service.CustomOAuth2UserService;
import com.example.authorize.oauth2.service.CustomOidcUserService;
import com.example.authorize.oauth2.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;
    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/static/js/**", "/static/images/**", "/static/css/**","/static/scss/**");
    }

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests((requests) -> requests
//                .antMatchers("/loginProc").permitAll()
                    .requestMatchers("/api/user")
                    .access(AuthenticatedAuthorizationManager.rememberMe())
//                .access("hasAuthority('SCOPE_profile')")
                    .requestMatchers("/api/oidc")
                    .access(AuthenticatedAuthorizationManager.rememberMe())
                //.access("hasAuthority('SCOPE_openid')")
                    .requestMatchers("/")
                                                    .permitAll()
                    .anyRequest().authenticated())
                        .formLogin(
                                    formLogin -> formLogin
                                                .loginPage("/login")
                                                .loginProcessingUrl("/loginProc")
                                                .defaultSuccessUrl("/")
                                                .permitAll())
                        .oauth2Login(oauth2 -> oauth2.userInfoEndpoint(
                                    userInfoEndpointConfig -> userInfoEndpointConfig
                                                            .userService(customOAuth2UserService)  // OAuth2
                                                            .oidcUserService(customOidcUserService)))  // OpenID Connect
                                                            .userDetailsService(customUserDetailsService) // Form
                        .exceptionHandling(exception -> exception.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                        .logout(logout -> logout
                                            .deleteCookies("remove")
                                            .logoutSuccessUrl("/")
                                            .invalidateHttpSession(false)
                                            .logoutUrl("/logoutUrl"))  //TODO: LogoutURL 입력
                .build();
    }

}