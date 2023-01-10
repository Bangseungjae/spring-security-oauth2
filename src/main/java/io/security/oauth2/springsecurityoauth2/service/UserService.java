package io.security.oauth2.springsecurityoauth2.service;

import io.security.oauth2.springsecurityoauth2.model.ProviderUser;
import io.security.oauth2.springsecurityoauth2.model.User;
import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public void register(String registrationId, ProviderUser providerUser) {
        User user = User.builder()
                .registrationId(registrationId)
                .username(providerUser.getUsername())
                .password(providerUser.getPassword())
                .email(providerUser.getEmail())
                .authorities(providerUser.getAuthorities())
                .id(providerUser.getId())
                .provider(providerUser.getProvider())
                .build();
        userRepository.register(user);
    }
}
