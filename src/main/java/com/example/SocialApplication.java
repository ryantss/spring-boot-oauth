package com.example;


import java.io.IOException;
import java.security.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

@SpringBootApplication
@EnableOAuth2Sso
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		return principal;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.antMatcher("/**")
			.authorizeRequests()
				.antMatchers("/", "/login**", "/webjars/**").permitAll()
			.anyRequest()
				.authenticated()
			.and().logout().logoutSuccessUrl("/").permitAll()
			.and().csrf().csrfTokenRepository(csrfTokenRepository())
			.and().addFilterAfter(csrfHHeaderFilter(), CsrfFilter.class);
	}

	// For angularJS, see https://spring.io/guides/tutorials/spring-boot-oauth2/#_social_login_logout
	private Filter csrfHHeaderFilter() {
		return new OncePerRequestFilter() {
			@Override
			protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
					FilterChain filterChain) throws ServletException, IOException {
				CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
				if (csrf != null) {
					Cookie cookieToken = WebUtils.getCookie(request, "XSRF-TOKEN");
					String csrfToken = csrf.getToken();
					if (cookieToken == null || csrfToken != null && !csrfToken.equals(cookieToken.getValue())) {
						cookieToken = new Cookie("XSRF-TOKEN", csrfToken);
						cookieToken.setPath("/");
						response.addCookie(cookieToken);
					}
				}
				filterChain.doFilter(request, response);
			}
		};
	}

	// For angularJS, see https://spring.io/guides/tutorials/spring-boot-oauth2/#_social_login_logout
	private CsrfTokenRepository csrfTokenRepository() {
		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.setHeaderName("X-XSRF-TOKEN");
		return repository;
	}

	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}
}
