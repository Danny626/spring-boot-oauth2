package com.example.authorizationserver.federated;

import com.example.authorizationserver.entity.GoogleUser;
import com.example.authorizationserver.repository.GoogleUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

@RequiredArgsConstructor
@Slf4j
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

//    private final UserRepository userRepository = new UserRepository();
    private final GoogleUserRepository googleUserRepository;

    /*@Override
    public void accept(OAuth2User user) {
        // Capture user in a local data store on first authentication
        if (this.userRepository.findByName(user.getName()) == null) {
            System.out.println("Saving first-time user: name=" + user.getName() + ", claims=" + user.getAttributes() + ", authorities=" + user.getAuthorities());
            this.userRepository.save(user);
        }
    }*/

    @Override
    public void accept(OAuth2User user) {
        // Capture user in a local data store on first authentication
        if (this.googleUserRepository.findByEmail(user.getName()).isEmpty()) {
            GoogleUser googleUser = GoogleUser.fromOauth2User(user);
            log.info(googleUser.toString());
            this.googleUserRepository.save(googleUser);
        } else {
            log.info("Bienvenido {}", user.getAttributes().get("given_name"));
        }
    }

    /*static class UserRepository {

        private final Map<String, OAuth2User> userCache = new ConcurrentHashMap<>();

        public OAuth2User findByName(String name) {
            return this.userCache.get(name);
        }

        public void save(OAuth2User oauth2User) {
            this.userCache.put(oauth2User.getName(), oauth2User);
        }

    }*/

}
