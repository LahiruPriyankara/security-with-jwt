package com.lhu.securitywithjwt.service;

import com.lhu.securitywithjwt.model.RegisteredUserDetails;
import com.lhu.securitywithjwt.model.UserDetailsEntity;
import com.lhu.securitywithjwt.model.UserRegisterRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Service
@Slf4j
public class UserManagementService implements UserDetailsService {

  private static final List<UserDetailsEntity> userDetailsEntityList = new ArrayList<>();

  public boolean registerUser(final UserRegisterRequest userRegisterRequest)
      throws UsernameNotFoundException {

    userDetailsEntityList.add(
        UserDetailsEntity.builder()
            .username(userRegisterRequest.getUsername())
            .password(new BCryptPasswordEncoder().encode(userRegisterRequest.getPassword()))
            .roles(userRegisterRequest.getRoles())
            .isAccountLocked(userRegisterRequest.getIsAccountLocked())
            .isCredentialsExpired(userRegisterRequest.getIsCredentialsExpired())
            .isAccountExpired(userRegisterRequest.getIsAccountExpired())
            .isEnabled(userRegisterRequest.getIsEnabled())
            .build());

    log.info("Registered Users - systemUserDetailsList: " + userDetailsEntityList);

    return Boolean.TRUE;
  }

  public UserDetailsEntity updateUser(
      String username,
      boolean isAccountExpired,
      boolean isAccountLocked,
      boolean isCredentialsExpired,
      boolean isEnabled)
      throws UsernameNotFoundException {

    UserDetailsEntity userDetailsEntity = findUserEntity(username);
    userDetailsEntity.setAccountExpired(isAccountExpired);
    userDetailsEntity.setAccountLocked(isAccountLocked);
    userDetailsEntity.setCredentialsExpired(isCredentialsExpired);
    userDetailsEntity.setEnabled(isEnabled);
    return userDetailsEntity;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    UserDetailsEntity userDetailsEntity = findUserEntity(username);

    UserDetails userDetails = new RegisteredUserDetails(userDetailsEntity);

    log.info("userDetails.getUsername(): " + userDetails.getUsername());
    log.info("userDetails.getPassword(): " + userDetails.getPassword());
    log.info("userDetails.getAuthorities(): " + userDetails.getAuthorities());
    log.info("userDetails.isAccountNonExpired(): " + userDetails.isAccountNonExpired());
    log.info("userDetails.isAccountNonLocked(): " + userDetails.isAccountNonLocked());
    log.info("userDetails.isCredentialsNonExpired(): " + userDetails.isCredentialsNonExpired());
    log.info("userDetails.isEnabled(): " + userDetails.isEnabled());

    return userDetails;
  }

  private UserDetailsEntity findUserEntity(String username) {
    UserDetailsEntity userDetailsEntity =
        userDetailsEntityList.stream()
            .filter(sysUser -> sysUser.getUsername().equals(username))
            .findAny()
            .orElse(null);

    if (Objects.isNull(userDetailsEntity)) {
      log.info("SystemUserDetails not fount for given user name : " + username);
      throw new UsernameNotFoundException("User not found.");
    }

    log.info("SystemUserDetails: " + userDetailsEntity);
    return userDetailsEntity;
  }
}
