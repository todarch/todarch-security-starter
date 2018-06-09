package com.todarch.security.domain.shared;

import lombok.NonNull;

public class Jwt {
  private final String token;

  private Jwt(String token) {
    this.token = token;
  }

  public static Jwt from(@NonNull String token) {
    return new Jwt(token);
  }

  public String token() {
    return token;
  }

  @Override
  public String toString() {
    return token();
  }
}
