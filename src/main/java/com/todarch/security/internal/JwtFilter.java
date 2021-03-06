package com.todarch.security.internal;

import com.todarch.security.api.JwtUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Filters incoming requests and installs a Spring Security principal
 * if a header corresponding to a valid user is found.
 */
public class JwtFilter extends GenericFilterBean {

  private JwtUtil jwtUtil;

  public JwtFilter(JwtUtil jwtUtil) {
    this.jwtUtil = jwtUtil;
  }

  @Override
  public void doFilter(ServletRequest servletRequest,
                       ServletResponse servletResponse,
                       FilterChain filterChain)
      throws IOException, ServletException {

    HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
    String jwt = resolveToken(httpServletRequest);

    if (StringUtils.hasText(jwt) && this.jwtUtil.validateToken(jwt)) {
      Authentication authentication = this.jwtUtil.getAuthentication(jwt);
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    filterChain.doFilter(servletRequest, servletResponse);
  }

  private String resolveToken(HttpServletRequest request) {
    String bearerToken = request.getHeader(JwtUtil.AUTH_HEADER);
    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(JwtUtil.AUTH_PREFIX)) {
      return bearerToken.substring(7, bearerToken.length());
    }
    return null;
  }
}

