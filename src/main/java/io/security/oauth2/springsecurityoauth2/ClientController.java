package io.security.oauth2.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

@Controller
public class ClientController {

    @Autowired
    private OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    @Autowired
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @GetMapping("/client")
    public String client(HttpServletRequest request, Model model) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String clientRegistrationId = "keycloak";

        OAuth2AuthorizedClient oAuth2AuthorizedClient1 = oAuth2AuthorizedClientRepository
                .loadAuthorizedClient(clientRegistrationId, authentication, request);

        OAuth2AuthorizedClient oAuth2AuthorizedClient2 = oAuth2AuthorizedClientService.
                loadAuthorizedClient(clientRegistrationId, authentication.getName());

        OAuth2AccessToken accessToken = oAuth2AuthorizedClient1.getAccessToken();

        OAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = oAuth2UserService
                .loadUser(new OAuth2UserRequest(oAuth2AuthorizedClient1.getClientRegistration(), accessToken));

        OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken
                (oAuth2User, Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")), oAuth2AuthorizedClient1.getClientRegistration().getRegistrationId());

        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);

        model.addAttribute("accessToken", accessToken.getTokenValue());
        model.addAttribute("refreshToken", oAuth2AuthorizedClient1.getRefreshToken().getTokenValue());
        model.addAttribute("principalName", oAuth2User.getName());
        model.addAttribute("clientName", oAuth2AuthorizedClient1.getClientRegistration().getClientName());

        return "client";
    }
}
