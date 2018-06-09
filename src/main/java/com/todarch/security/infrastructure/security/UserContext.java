package com.todarch.security.infrastructure.security;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Data
public class UserContext {
  private Long userId;
  private String email;
  private Collection<? extends GrantedAuthority> authorities;
}
