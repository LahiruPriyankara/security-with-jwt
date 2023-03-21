package com.lhu.securitywithjwt.model;

import com.lhu.securitywithjwt.utils.UserRoleEnum;
import lombok.*;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class UserDetailsEntity {

    private String username;
    private String password;
    private List<UserRoleEnum> roles;
    private boolean isAccountExpired;
    private boolean isAccountLocked;
    private boolean isCredentialsExpired;
    private boolean isEnabled;
}
