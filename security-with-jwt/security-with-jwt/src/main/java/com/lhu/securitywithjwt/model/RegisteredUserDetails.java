package com.lhu.securitywithjwt.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class RegisteredUserDetails extends UserDetailsEntity implements UserDetails {

  private final UserDetailsEntity userDetailsEntity;

  public RegisteredUserDetails(UserDetailsEntity user) {
    this.userDetailsEntity = user;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
    userDetailsEntity.getRoles()
        .forEach(userRole -> authorities.add(new SimpleGrantedAuthority(userRole.name())));

    return authorities;
  }

  @Override
  public String getPassword() {
    return userDetailsEntity.getPassword();
  }

  @Override
  public String getUsername() {
    return userDetailsEntity.getUsername();
  }

  @Override
  public boolean isAccountNonExpired() {
    return !userDetailsEntity.isAccountExpired();
  }

  @Override
  public boolean isAccountNonLocked() {
    return !userDetailsEntity.isAccountLocked();
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return !userDetailsEntity.isCredentialsExpired();
  }

  @Override
  public boolean isEnabled() {
    return userDetailsEntity.isEnabled();
  }
}
