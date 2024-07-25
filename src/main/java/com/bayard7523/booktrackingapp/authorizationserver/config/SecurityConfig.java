package com.bayard7523.booktrackingapp.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(authorize ->
				authorize.anyRequest().authenticated()
		);

		return http.formLogin(Customizer.withDefaults()).build();
	}

	@Bean
	public UserDetailsService users() {
		final UserDetails adminUser = User.builder()
				.username("admin")
				.password("{noop}admin")
				.roles("ADMIN")
				.build();

		final UserDetails user = User.builder()
				.username("user")
				.password("{noop}user")
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(user, adminUser);
	}
}
