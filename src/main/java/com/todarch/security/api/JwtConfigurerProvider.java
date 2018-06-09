package com.todarch.security.api;

import com.todarch.security.internal.JwtConfigurer;

public final class JwtConfigurerProvider {

  public JwtConfigurer get() {
    return new JwtConfigurer(new JwtUtil());
  }
}
