package com.lhu.securitywithjwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserAuthRequest {
  @NotBlank private String username;
  @NotBlank private String password;
}
