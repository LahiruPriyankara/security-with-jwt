package com.lhu.securitywithjwt.model;

import com.lhu.securitywithjwt.utils.UserRoleEnum;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class UserRegisterRequest {

  @NotBlank private String username;
  @NotBlank private String password;
  @NotNull @NotEmpty private List<UserRoleEnum> roles;
  @NotNull private Boolean isAccountExpired;
  @NotNull private Boolean isAccountLocked;
  @NotNull private Boolean isCredentialsExpired;
  @NotNull private Boolean isEnabled;
}
