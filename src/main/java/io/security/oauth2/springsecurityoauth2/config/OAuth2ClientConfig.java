package io.security.oauth2.springsecurityoauth2.config;

import io.security.oauth2.springsecurityoauth2.CustomAuthorityMapper;
import io.security.oauth2.springsecurityoauth2.service.CustomOAuth2UserService;
import io.security.oauth2.springsecurityoauth2.service.CustomOidcUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.Filter;

@EnableWebSecurity
public class OAuth2ClientConfig {

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    private CustomOidcUserService customOidcUserService;


    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> web.ignoring().antMatchers(
                "/static/js/**", "/static/images/**", "/static/css/**", "/static/icon/**", "/static/scss/**"
        ));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authRequest -> authRequest
                .antMatchers("/api/user").hasAnyRole("SCOPE_profile", "SCOPE_email")
                .antMatchers("/api/oidc").hasAnyRole("SCOPE_openid")
                        .antMatchers("/","/oauth2Login").permitAll()
                        .anyRequest().authenticated());

        http.oauth2Login(oauth2 -> oauth2.userInfoEndpoint(
                userInfoEndpointConfig -> userInfoEndpointConfig
                        .userService(customOAuth2UserService)
                        .oidcUserService(customOidcUserService)
        ));

//        http.oauth2Client(Customizer.withDefaults());
        http.logout().logoutSuccessUrl("/");

        return http.build();
    }

    @Bean
    public GrantedAuthoritiesMapper customAuthorityMapper() {
        return new CustomAuthorityMapper();
    }

}
