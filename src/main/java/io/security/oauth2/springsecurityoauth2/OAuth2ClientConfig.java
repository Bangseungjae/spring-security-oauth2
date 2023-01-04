package io.security.oauth2.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@EnableWebSecurity
public class OAuth2ClientConfig {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        return new InMemoryClientRegistrationRepository(keyCloakClientRegistration());
//    }
//
//    private ClientRegistration keyCloakClientRegistration() {
//        return ClientRegistrations.fromIssuerLocation("http://localhost:8080/realms/oauth2") // 인가 서버로부터 정보를 가져온다.(가장 쉬운 방식)
//                .registrationId("keycloak")
//                .clientId("oauth2-client-app") // 필수
//                .clientSecret("KaUeVyCxo76S4M662vOw8NJ1NWNtAD0s") // 필수
//                .redirectUri("http://localhost:8081/login/oauth2/code/keycloack") // 필수X
////                .issuerUri("")
//                .userInfoUri("http://localhost:8080/realms/oauth2/protocol/openid-connect/userinfo")
//                .build();
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(authRequest -> authRequest.antMatchers("/home").permitAll()
//                .anyRequest().authenticated());
//        http.oauth2Login(authLogin -> authLogin.authorizationEndpoint(
//                authEndpoint -> authEndpoint.authorizationRequestResolver(customOAuth2AuthorizationRequestResolver())
//        ));
//        http.logout().logoutSuccessUrl("/home");
        http.authorizeHttpRequests(authRequest -> authRequest
                        .antMatchers("/home", "/client").permitAll()
                        .anyRequest().authenticated());
        http
                .oauth2Client(Customizer.withDefaults());
        http.logout().logoutSuccessUrl("/home");

        return http.build();
    }

    private OAuth2AuthorizationRequestResolver customOAuth2AuthorizationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri("http://localhost:8081/login");
        return successHandler;
    }
}
