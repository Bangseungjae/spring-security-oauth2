package io.security.oauth2.springsecurityoauth2.service;

import io.security.oauth2.springsecurityoauth2.converters.ProviderUserConverter;
import io.security.oauth2.springsecurityoauth2.converters.ProviderUserRequest;
import io.security.oauth2.springsecurityoauth2.model.*;
import io.security.oauth2.springsecurityoauth2.model.social.GoogleUser;
import io.security.oauth2.springsecurityoauth2.model.social.KeycloakUser;
import io.security.oauth2.springsecurityoauth2.model.social.NaverUser;
import io.security.oauth2.springsecurityoauth2.model.users.User;
import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Getter
public class AbstractOAuth2UserService {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ProviderUserConverter<ProviderUserRequest, ProviderUser> providerUserConverter;

    protected void register(ProviderUser providerUser, OAuth2UserRequest userRequest) {
        User user = userRepository.findByUsername(providerUser.getUsername());

        if (user == null) {
            String registrationId = userRequest.getClientRegistration().getRegistrationId();
            userService.register(registrationId, providerUser);
        }else {
            System.out.println("user = " + user);
        }
    }


    protected ProviderUser providerUser(ProviderUserRequest providerUserRequest) {

        return providerUserConverter.converter(providerUserRequest);
    }
}
