package com.example;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class TestSpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(TestSpringSecurityApplication.class, args);
	}
}

@Configuration
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private AuthFilter authFilter;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.addFilterAfter(authFilter, SecurityContextPersistenceFilter.class)
			.headers().and()
			.formLogin().disable()
			.httpBasic().disable()
			.csrf().disable()
			.authorizeRequests()
				.antMatchers("/test").hasAnyRole("USER", "ADMIN")
				.antMatchers("/admin").hasRole("ADMIN")
				.anyRequest().authenticated();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("test").password("testing").roles("USER").and()
			.withUser("admin").password("admin").roles("ADMIN", "USER");
	}
	
	/*
	 * Disable default registration
	 */
	@Bean
	public FilterRegistrationBean authFilterRegistraitionDisable (AuthFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean(filter);
		registration.setEnabled(false);
		
		return registration;
	}
}

@RestController
class TestRest {
	
	@RequestMapping("test")
	public String test() {
		return "Hello World " + new Date().toString();
	}
	
	@RequestMapping("admin")
	public String admin() {
		return "ADMIN Hello World " + new Date().toString();
	}
}

@Component
class AuthFilter implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		/*
		 * Authority in Spring Security is always prefixed ROLE_ with role (USER role is ROLE_USER authority, ADMIN role is ROLE_ADMIN authority) 
		 */
		List<SimpleGrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
		User user = new User("test", "autologin", authorities);
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
		
		SecurityContextHolder.getContext().setAuthentication(authentication);

		System.out.println("Created authentication for test");
		
		chain.doFilter(request, response);
	}
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		
	}

	@Override
	public void destroy() {
		
	}
	
}