package com.lhu.securitywithjwt.config;

import com.lhu.securitywithjwt.service.UserManagementService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Component
public class JWTAuthTokenFilter extends OncePerRequestFilter {

  private final JWTUtility jwtUtility;
  private final UserManagementService userManagementService;

  public JWTAuthTokenFilter(JWTUtility jwtUtility, UserManagementService userManagementService) {
    this.jwtUtility = jwtUtility;
    this.userManagementService = userManagementService;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse,
      FilterChain filterChain)
      throws ServletException, IOException {

    String authorization = httpServletRequest.getHeader("Authorization");
    String token;
    String userName = null;

    if (Objects.nonNull(authorization) && authorization.startsWith("Bearer ")) {
      token = authorization.substring(7);
      //Token validation also handle
      userName = jwtUtility.getUsernameFromToken(token);
    }

    if (Objects.nonNull(userName)
        && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {

      UserDetails userDetails = userManagementService.loadUserByUsername(userName);

      UsernamePasswordAuthenticationToken authentication =
          new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

      authentication.setDetails(
          new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));

      SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    filterChain.doFilter(httpServletRequest, httpServletResponse);
  }
}
