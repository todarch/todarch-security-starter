package com.todarch.security.api;

import com.todarch.security.api.UserContext;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@Slf4j
//TODO:selimssevgi: write tests
public class JwtUtil {

  private static final String AUTHORITIES_KEY = "auth";
  private static final String USER_ID_KEY = "user_id";
  public static final String AUTH_HEADER = "Authorization";
  public static final String AUTH_PREFIX = "Bearer ";

  private String secretKey = "secret";

  private long tokenValidityInMilliseconds = 1000 * 3000L;

  private long tokenValidityInMillisecondsForRememberMe = 1000 * 8000L;

  private Claims getAllClaimsFromToken(String token) {
    return Jwts.parser()
        .setSigningKey(secretKey)
        .parseClaimsJws(token)
        .getBody();
  }

  /**
   * Creates jwt based on Authentication object.
   *
   * @param authentication spring security authentication
   * @param rememberMe changes the expire date of jwt
   * @return token
   */
  public String createToken(Authentication authentication, Boolean rememberMe, Long userId) {
    String authorities = authentication.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(","));

    //TODO:selimssevgi: use java 8
    long now = (new Date()).getTime();
    Date validity;
    if (rememberMe) {
      validity = new Date(now + this.tokenValidityInMillisecondsForRememberMe);
    } else {
      validity = new Date(now + this.tokenValidityInMilliseconds);
    }

    return Jwts.builder()
        .setSubject(authentication.getName())
        .claim(AUTHORITIES_KEY, authorities)
        .claim(USER_ID_KEY, userId)
        .signWith(SignatureAlgorithm.HS512, secretKey)
        .setExpiration(validity)
        .compact();
  }

  /**
   * Construct authentication object based on token.
   *
   * @param token authentication token
   * @return spring security authentication
   */
  public Authentication getAuthentication(String token) {
    Claims claims = getAllClaimsFromToken(token);

    Collection<? extends GrantedAuthority> authorities =
        Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

    Long userId = claims.get(USER_ID_KEY, Long.class);

    UserContext principal = new UserContext(
        token,
        userId,
        claims.getSubject(),
        authorities);

    return new UsernamePasswordAuthenticationToken(principal, token, authorities);
  }

  /**
   * Validates token in memory.
   *
   * @param authToken authentication token
   * @return true if jwt is valid for the system, otherwise false
   */
  public boolean validateToken(String authToken) {
    try {
      Jwts.parser().setSigningKey(secretKey).parseClaimsJws(authToken);
      return true;
    } catch (SignatureException e) {
      log.info("Invalid JWT signature.");
      log.trace("Invalid JWT signature trace: {}", e);
    } catch (MalformedJwtException e) {
      log.info("Invalid JWT token.");
      log.trace("Invalid JWT token trace: {}", e);
    } catch (ExpiredJwtException e) {
      log.info("Expired JWT token.");
      log.trace("Expired JWT token trace: {}", e);
    } catch (UnsupportedJwtException e) {
      log.info("Unsupported JWT token.");
      log.trace("Unsupported JWT token trace: {}", e);
    } catch (IllegalArgumentException e) {
      log.info("JWT token compact of handler are invalid.");
      log.trace("JWT token compact of handler are invalid trace: {}", e);
    }
    return false;
  }
}

