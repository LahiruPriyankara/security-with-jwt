package com.lhu.securitywithjwt.config;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@Slf4j
public class JWTUtility implements Serializable {

  private static final long serialVersionUID = 234234523523L;

  @Value("${jwt.secret.key}")
  private String secretKey;

  // while creating the token -
  // 1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
  // 2. Sign the JWT using the HS512 algorithm and secret key.
  private String doGenerateToken(Map<String, Object> claims, UserDetails userDetails) {

    final String token =
        Jwts.builder()
            .setClaims(claims)
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(
                new Date(
                    System.currentTimeMillis()
                        + (10 * 60
                            * 1000))) /* After issuing the token, It will be valid until 10 minutes*/
            .signWith(SignatureAlgorithm.HS512, secretKey)
            .compact();
    log.info("Token : " + token);
    return token;
  }

  // validate token
  public void validateToken(String token) {
    boolean isValidToken = false;
    try {
      Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
      isValidToken = true;
    } catch (SignatureException e) {
      log.error("Invalid JWT signature: {}", e.getMessage());
    } catch (MalformedJwtException e) {
      log.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      log.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      log.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      log.error("JWT claims string is empty: {}", e.getMessage());
    }
    log.info("IsValidToken : " + isValidToken);
  }

  // retrieve username from jwt token
  public String getUsernameFromToken(String token) {
    validateToken(token);
    return getClaimFromToken(token, Claims::getSubject);
  }

  // retrieve expiration date from jwt token
  public Date getExpirationDateFromToken(String token) {
    return getClaimFromToken(token, Claims::getExpiration);
  }

  public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = getAllClaimsFromToken(token);
    return claimsResolver.apply(claims);
  }

  // for retrieving any information from token we will need the secret key
  private Claims getAllClaimsFromToken(String token) {
    return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
  }

  // check if the token has expired
  private Boolean isTokenExpired(String token) {
    final Date expiration = getExpirationDateFromToken(token);
    return expiration.before(new Date());
  }

  // generate token for user
  public String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    return doGenerateToken(claims, userDetails);
  }
}
