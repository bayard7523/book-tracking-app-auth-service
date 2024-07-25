package com.bayard7523.booktrackingapp.authorizationserver.config;

import com.bayard7523.booktrackingapp.authorizationserver.util.JWKUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.List;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.*;

@RequiredArgsConstructor
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	private final OAuth2AuthorizationServerProperties authorizationServerProperties;

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http.exceptionHandling(exceptions ->
				exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
		);

		return http.build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		return new InMemoryRegisteredClientRepository(
				RegisteredClient.withId("test-client-id")
						.clientName("Test Client")
						.clientId("test-client")
						.clientSecret("{noop}test-client")
						.redirectUri("http://localhost:5000/code")
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantTypes(authorizationGrantTypes ->
								authorizationGrantTypes
										.addAll(List.of(CLIENT_CREDENTIALS, AUTHORIZATION_CODE, REFRESH_TOKEN)))
						.build()
		);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		final RSAKey rsaKey = JWKUtils.generateRsa();
		final JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, context) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
				.issuer(authorizationServerProperties.getIssuer())
				.build();
	}
}
