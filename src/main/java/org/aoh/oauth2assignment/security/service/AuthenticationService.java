package org.aoh.oauth2assignment.security.service;

import org.aoh.oauth2assignment.security.auth.AuthenticationRequestDto;
import org.aoh.oauth2assignment.security.auth.AuthenticationResponseDto;
import org.aoh.oauth2assignment.security.auth.RegisterRequestDto;
import org.aoh.oauth2assignment.security.entity.User;
import org.aoh.oauth2assignment.security.repo.UserRepository;
import org.aoh.oauth2assignment.shared.MessageConstant;
import org.aoh.oauth2assignment.shared.UserResponse;
import org.aoh.oauth2assignment.shared.exception.UserAlreadyExistException;
import org.aoh.oauth2assignment.shared.exception.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository repository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  /**
   * Registers a new user.
   *
   * @param request the registration request data.
   * @return UserResponse indicating the result of the registration.
   * @throws UserAlreadyExistException if the user with the given email already exists.
   * @since 2 May 2024
   */
  public UserResponse register(RegisterRequestDto request) {
    Optional<User> optionalUser = repository.findByEmail(request.getEmail());
    if (optionalUser.isPresent()) {
      log.info("user registered already");
      throw new UserAlreadyExistException(MessageConstant.ALREADY_REGISTER_USER);
    }
    log.info("NoDuplicateEmail");
    var user = User.builder()
            .fullName(request.getFullName())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .build();
    repository.save(user);
    return new UserResponse(MessageConstant.ACCOUNT_CREATION_SUCCESSFUL);
  }

  /**
   * Authenticates a user.
   *
   * @param request the authentication request data.
   * @return AuthenticationResponseDto containing JWT tokens.
   * @throws UserNotFoundException if the user is not found.
   * @since 2 May 2024
   */
  public AuthenticationResponseDto authenticate(AuthenticationRequestDto request) {
    log.info("login or authenticating");
    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
    var user = repository.findByEmail(request.getEmail()).orElseThrow(() -> {
      log.error("User Not Found");
      throw new UserNotFoundException(MessageConstant.USER_NOT_FOUND);
    });
    List<String> jwtList = jwtService.generateToken(user);
    return new AuthenticationResponseDto(jwtList.get(0), jwtList.get(1), MessageConstant.ACCOUNT_LOGGED_IN_SUCCESSFULLY);
  }
}
