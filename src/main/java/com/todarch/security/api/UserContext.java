package com.todarch.security.api;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
@AllArgsConstructor
public class UserContext {
  private final String jwt;
  private final Long userId;
  private final String email;
  private final Collection<? extends GrantedAuthority> authorities;
}
