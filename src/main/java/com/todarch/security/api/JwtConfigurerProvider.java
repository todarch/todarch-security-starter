package com.todarch.security.api;

import com.todarch.security.internal.JwtConfigurer;

public final class JwtConfigurerProvider {

  private JwtConfigurerProvider() {
    throw new AssertionError("No instance of utility class");
  }

  public static JwtConfigurer get() {
    return new JwtConfigurer(new JwtUtil());
  }
}
