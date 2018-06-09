package com.todarch.security.api;

import com.todarch.security.api.UserContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

/**
 * Utility class for Spring Security.
 */
public final class SecurityUtil {

  private SecurityUtil() {
    throw new AssertionError("Cannot create object of utility class");
  }

  /**
   * Get the user context of the current user.
   *
   * @return the context of the current user
   */
  public static Optional<UserContext> getUserContext() {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    return Optional.ofNullable(securityContext.getAuthentication())
        .map(
            authentication -> {
              if (authentication.getPrincipal() instanceof UserContext) {
                return (UserContext) authentication.getPrincipal();
              }
              return null;
            });
  }

  /**
   * Gets the login of the current user.
   *
   * @return the login of the current user
   * @throws RuntimeException if not logged-in user found
   */
  public static UserContext tryToGetUserContext() {
    return getUserContext()
        //TODO:selimssevgi: fix this exception
        .orElseThrow(() -> new RuntimeException("Not logged-in user found"));
  }
}

