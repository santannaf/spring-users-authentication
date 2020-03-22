package com.spring.users.auth.security.user;

import com.spring.users.auth.model.ApplicationUser;
import com.spring.users.auth.repository.ApplicationUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotNull;
import java.util.Collection;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Component
@Slf4j
public class UserDetailsserviceImpl implements UserDetailsService {

    private final ApplicationUserRepository applicationUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        log.info("Searching in the DB the user by username '{}'", username);

        ApplicationUser applicationUser = applicationUserRepository.findByUsername(username);

        log.info("Application user found '{}'", applicationUser);

        if (applicationUser == null) throw new UsernameNotFoundException(String.format("Application user '%s' not found", username));

        return new CustomerUserDetails(applicationUser);
    }

    private static final class CustomerUserDetails extends ApplicationUser implements UserDetails {

        CustomerUserDetails(@NotNull ApplicationUser applicationUser) {
            super(applicationUser);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_" + this.getRole());
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}