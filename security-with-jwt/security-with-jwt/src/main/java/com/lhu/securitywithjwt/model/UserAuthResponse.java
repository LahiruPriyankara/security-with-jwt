package com.lhu.securitywithjwt.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserAuthResponse {
  @JsonProperty("isAuthenticated")
  private boolean isAuthenticated;

  private String jwtToken;
}
