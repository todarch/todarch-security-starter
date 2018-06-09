package com.todarch.security.internal;

import com.todarch.security.api.JwtUtil;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtConfigurer extends
    SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

  private JwtUtil jwtUtil;

  public JwtConfigurer(JwtUtil jwtUtil) {
    this.jwtUtil = jwtUtil;
  }

  @Override
  public void configure(HttpSecurity http) throws Exception {
    JwtFilter customFilter = new JwtFilter(jwtUtil);
    http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
  }
}
