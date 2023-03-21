package com.lhu.securitywithjwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SecurityWithJwtApplication {

  public static void main(String[] args) {
    SpringApplication.run(SecurityWithJwtApplication.class, args);
  }

}
