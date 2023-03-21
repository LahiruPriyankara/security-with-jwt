package com.lhu.securitywithjwt.controller;

import com.lhu.securitywithjwt.config.JWTUtility;
import com.lhu.securitywithjwt.model.UserAuthRequest;
import com.lhu.securitywithjwt.model.UserAuthResponse;
import com.lhu.securitywithjwt.model.UserRegisterRequest;
import com.lhu.securitywithjwt.service.UserManagementService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("app")
@Slf4j
public class AppController {

  private final UserManagementService userManagementService;
  private final JWTUtility jwtUtility;
  private final AuthenticationManager authenticationManager;

  public AppController(
      UserManagementService userManagementService,
      JWTUtility jwtUtility,
      AuthenticationManager authenticationManager) {
    this.userManagementService = userManagementService;
    this.jwtUtility = jwtUtility;
    this.authenticationManager = authenticationManager;
  }

  @PostMapping("user/register")
  public ResponseEntity<Boolean> userRegister(
      @RequestBody @Valid UserRegisterRequest userRegisterRequest) {

    log.info(
        "AppController.userRegister called..userRegisterRequest.toString():"
            + userRegisterRequest.toString());

    return ResponseEntity.ok(userManagementService.registerUser(userRegisterRequest));
  }

  @PostMapping("user/authenticate")
  public ResponseEntity<UserAuthResponse> userAuthenticate(
      @RequestBody @Valid UserAuthRequest userAuthRequest) {

    log.info(
        "AppController.userAuthenticate called..userAuthRequest.toString():"
            + userAuthRequest.toString());

    boolean isAuthenticated = Boolean.FALSE;
    String jwtToken = null;
    try {
      authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(
              userAuthRequest.getUsername(), userAuthRequest.getPassword()));
      final UserDetails userDetails =
          userManagementService.loadUserByUsername(userAuthRequest.getUsername());

      jwtToken = jwtUtility.generateToken(userDetails);
      isAuthenticated = Boolean.TRUE;

    } catch (BadCredentialsException e) {
      log.error("Authentication Failed.", e);
    }
    return ResponseEntity.ok(
        UserAuthResponse.builder().isAuthenticated(isAuthenticated).jwtToken(jwtToken).build());
  }

  @DeleteMapping("delete")
  public ResponseEntity<String> testDeleteMethod() {
    log.info("AppController.testDeleteMethod called..");
    return ResponseEntity.ok("AppController.testDeleteMethod called..");
  }

  // @PreAuthorize("hasAuthority('ADMIN') or hasAuthority('CLIENT')")
  // @Secured({"ADMIN"})
  // or @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  @GetMapping("/admin/get")
  // @PreAuthorize("hasAuthority('ADMIN')")
  public ResponseEntity<String> testAdminGetMethod() {
    log.info("AppController.testAdminGetMethod called..");
    return ResponseEntity.ok("AppController.testAdminGetMethod called..");
  }

  @GetMapping("client/get")
  public ResponseEntity<String> testClientGetMethod() {
    log.info("AppController.testClientGetMethod called..");
    return ResponseEntity.ok("AppController.testClientGetMethod called..");
  }

  @GetMapping("admin-client/get")
  public ResponseEntity<String> testAdminClientGetMethod() {
    log.info("AppController.testAdminClientGetMethod called..");
    return ResponseEntity.ok("AppController.testAdminClientGetMethod called..");
  }

  @GetMapping("common/get")
  public ResponseEntity<String> testCommonGetMethod() {
    log.info("AppController.testCommonGetMethod called..");
    return ResponseEntity.ok("AppController.testGetMethod called..");
  }

  @GetMapping("refresh-token/get")
  public ResponseEntity<?> testRefreshTokenMethod(
      @RequestParam(name = "username", defaultValue = "1") String username) {
    log.info("AppController.testRefreshTokenMethod called..");

    boolean isAuthenticated = Boolean.FALSE;
    String jwtToken = null;
    try {
      final UserDetails userDetails = userManagementService.loadUserByUsername(username);

      jwtToken = jwtUtility.generateToken(userDetails);
      isAuthenticated = Boolean.TRUE;

    } catch (BadCredentialsException e) {
      log.error("Authentication Failed.", e);
    }
    return ResponseEntity.ok(
        UserAuthResponse.builder().isAuthenticated(isAuthenticated).jwtToken(jwtToken).build());
  }

  @PutMapping("update")
  public ResponseEntity<?> updateUserAccount(
      @RequestParam(name = "username", defaultValue = "1") String username,
      @RequestParam(name = "isAccountExpired", defaultValue = "0") boolean isAccountExpired,
      @RequestParam(name = "isAccountLocked", defaultValue = "0") boolean isAccountLocked,
      @RequestParam(name = "isCredentialsExpired", defaultValue = "0") boolean isCredentialsExpired,
      @RequestParam(name = "isEnabled", defaultValue = "1") boolean isEnabled) {

    log.info("AppController.updateUserAccount called..");

    return ResponseEntity.ok(
        userManagementService.updateUser(
            username, isAccountExpired, isAccountLocked, isCredentialsExpired, isEnabled));
  }
}
