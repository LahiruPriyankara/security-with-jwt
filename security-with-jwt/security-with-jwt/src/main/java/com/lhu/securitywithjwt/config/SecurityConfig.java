package com.lhu.securitywithjwt.config;

import com.lhu.securitywithjwt.utils.UserRoleEnum;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 01. NEW WAY...........................................................................

// *
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

  private final JWTAuthTokenFilter jwtAuthTokenFilter;

  public SecurityConfig(JWTAuthTokenFilter jwtFilter) {
    this.jwtAuthTokenFilter = jwtFilter;
  }

  /*  @Bean
  public UserDetailsService userDetailsService(BCryptPasswordEncoder bCryptPasswordEncoder) {
      InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
      manager.createUser(User.withUsername("user")
              .password(bCryptPasswordEncoder.encode("userPass"))
              .roles("USER")
              .build());
      manager.createUser(User.withUsername("admin")
              .password(bCryptPasswordEncoder.encode("adminPass"))
              .roles("USER", "ADMIN")
              .build());
      return manager;
  }  */

  @Bean
  public PasswordEncoder passwordEncoder() {
    // PasswordEncoderFactories.createDelegatingPasswordEncoder();
    return new BCryptPasswordEncoder();
  }

  // This is the method for user authenticate
  @Bean
  public AuthenticationManager authenticationManager(
      HttpSecurity http,
      BCryptPasswordEncoder bCryptPasswordEncoder,
      UserDetailsService userDetailService)
      throws Exception {
    return http.getSharedObject(AuthenticationManagerBuilder.class)
        .userDetailsService(userDetailService)
        .passwordEncoder(bCryptPasswordEncoder)
        .and()
        .build();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    http.csrf()
        .disable()
        .authorizeRequests()
        .antMatchers(HttpMethod.DELETE)
        .hasAnyAuthority(UserRoleEnum.ADMIN.name())
        .antMatchers("/app/admin/**")
        .hasAnyAuthority(UserRoleEnum.ADMIN.name())
        .antMatchers("/app/client/**")
        .hasAnyAuthority(UserRoleEnum.CLIENT.name())
        .antMatchers("/app/admin-client/**")
        .hasAnyAuthority(UserRoleEnum.ADMIN.name(), UserRoleEnum.CLIENT.name())
        .antMatchers(
            "/app/user/register", "/app/user/authenticate", "/app/refresh-token/get", "/app/update")
        .permitAll()
        .anyRequest()
        .authenticated()
        .and()
        .httpBasic()
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    http.addFilterBefore(jwtAuthTokenFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
}
/*/


*/
// 02. OLD WAY...........................................................................
/*
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired private UserManagementService userManagementService;

  @Autowired private JWTFilter jwtFilter;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {

    auth.userDetailsService(userManagementService);
  }

  @Override
  @Bean
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf()
        .disable()
        .authorizeRequests()
        .antMatchers("/app/user/register", "/app/user/authenticate")
        .permitAll()
        .anyRequest()
        .authenticated()
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
  }
}
*/
