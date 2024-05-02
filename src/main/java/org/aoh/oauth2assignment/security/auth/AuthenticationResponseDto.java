package org.aoh.oauth2assignment.security.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponseDto {
  private String accessToken;
  private String refreshToken;
  private String responseMessage;
}
