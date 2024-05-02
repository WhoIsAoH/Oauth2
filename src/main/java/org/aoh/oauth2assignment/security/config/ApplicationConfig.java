package org.aoh.oauth2assignment.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aoh.oauth2assignment.security.repo.UserRepository;
import org.aoh.oauth2assignment.shared.MessageConstant;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

  private final UserRepository repository;

  /**
   * Fetches user details by email.
   *
   * @return UserDetailsService to load user details.
   * @throws UsernameNotFoundException if no user is found.
   * @author Ajaya Paudel
   * @since 2 May 2024
   */
  @Bean
  public UserDetailsService userDetailsService() {
    return username -> repository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException(MessageConstant.USER_NOT_FOUND));
  }

  /**
   * Configures the authentication provider with user details and password encoder.
   *
   * @return Configured AuthenticationProvider.
   * @author Ajaya Paudel
   * @since 2 May 2024
   */
  @Bean
  public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService());
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;
  }

  /**
   * Retrieves the configured AuthenticationManager.
   *
   * @param config the authentication configuration.
   * @return Configured AuthenticationManager.
   * @throws Exception if retrieval fails.
   * @since 2 May 2024
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
  }

  /**
   * Provides a BCrypt password encoder.
   *
   * @return BCryptPasswordEncoder instance.
   * @author Ajaya Paudel
   * @since 2 May 2024
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
