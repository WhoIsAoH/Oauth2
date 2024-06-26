package org.aoh.oauth2assignment.security.controller;


import org.aoh.oauth2assignment.security.auth.AuthenticationRequestDto;
import org.aoh.oauth2assignment.security.auth.AuthenticationResponseDto;
import org.aoh.oauth2assignment.security.auth.RegisterRequestDto;
import org.aoh.oauth2assignment.security.service.AuthenticationService;
import org.aoh.oauth2assignment.shared.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

  private final AuthenticationService service;

  /**
   * Registers a new user.
   *
   * @param request the registration request data
   * @return UserResponse indicating the result of the registration
   */
  @PostMapping("/register")
  public UserResponse register(@RequestBody @Validated RegisterRequestDto request) {
    return service.register(request);
  }

  /**
   * Authenticates a user.
   *
   * @param request the authentication request data
   * @return AuthenticationResponseDto containing authentication result
   */
  @PostMapping("/authenticate")
  public AuthenticationResponseDto authenticate(@RequestBody AuthenticationRequestDto request) {
    return service.authenticate(request);
  }

}
