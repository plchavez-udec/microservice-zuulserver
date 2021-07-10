package co.edu.ierdminayticha.sgd.zuulserver.oauth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@RefreshScope
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	
	private static final String ENDPOINT_BASE_TRD = "/api-trd/**";
	private static final String ENDPOINT_BASE_USERS = "/api-user/**";
	private static final String ENDPOINT_BASE_FORDERS = "/api-folders/%s";
	private static final String ENDPOINT_BASE_DOCUMENTS = "/api-documents/**";
	private static final String ROLE_ADMIN = "ADMIN";
	private static final String ROLE_SECRETARIO = "SECRETARIO";
	
	@Value("${config.security.oauth.jwt.key}")
	private String jwtKey;
	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore());
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/api/security/**").permitAll()
				// Microservicio de usuarios
				.antMatchers(HttpMethod.POST, ENDPOINT_BASE_USERS).hasRole(ROLE_ADMIN)
				.antMatchers(HttpMethod.GET, ENDPOINT_BASE_USERS).hasRole(ROLE_ADMIN)
				// Microservicio trd
				.antMatchers(HttpMethod.POST, ENDPOINT_BASE_TRD).hasRole(ROLE_ADMIN)
				.antMatchers(HttpMethod.GET, ENDPOINT_BASE_TRD).permitAll()
				.antMatchers(HttpMethod.PUT, ENDPOINT_BASE_TRD).hasRole(ROLE_ADMIN)
				.antMatchers(HttpMethod.PATCH, ENDPOINT_BASE_TRD).hasRole(ROLE_ADMIN)
				.antMatchers(HttpMethod.DELETE, ENDPOINT_BASE_TRD).hasRole(ROLE_ADMIN)
				// Microservicio carpetas
				.antMatchers(HttpMethod.POST, String.format(ENDPOINT_BASE_FORDERS, "**")).hasRole(ROLE_ADMIN)
				.antMatchers(HttpMethod.GET, String.format(ENDPOINT_BASE_FORDERS, "**")).permitAll()
				.antMatchers(HttpMethod.PATCH, String.format(ENDPOINT_BASE_FORDERS, "**")).hasRole(ROLE_ADMIN)
				.antMatchers(HttpMethod.DELETE, String.format(ENDPOINT_BASE_FORDERS, "**")).hasRole(ROLE_ADMIN)
				// Microservicio binarios
				.antMatchers(HttpMethod.POST, "/api-files/**").hasAnyRole(ROLE_ADMIN, ROLE_SECRETARIO)
				.antMatchers(HttpMethod.GET, "/api-files/**").hasAnyRole(ROLE_ADMIN, ROLE_SECRETARIO)
				// Microservicio binarios
				.antMatchers(HttpMethod.POST,  ENDPOINT_BASE_DOCUMENTS).hasAnyRole(ROLE_ADMIN, ROLE_SECRETARIO)
				.antMatchers(HttpMethod.GET,   ENDPOINT_BASE_DOCUMENTS).permitAll()
				.antMatchers(HttpMethod.PATCH, ENDPOINT_BASE_DOCUMENTS).permitAll()
				.anyRequest().authenticated()
				.and().cors().configurationSource(corsConfigurationSource());// COnsigurar quien puede cpnsumir el servicio

		;
	}
	
	// COnsigurar quien puede cpnsumir el servicio
	@Bean
	public  CorsConfigurationSource corsConfigurationSource() {
		
		CorsConfiguration corsConfiguration = new CorsConfiguration();
		corsConfiguration.setAllowedOrigins(Arrays.asList("*")); // Define que todsos pueden acceder
		corsConfiguration.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
		corsConfiguration.setAllowCredentials(true);
		corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
		
		UrlBasedCorsConfigurationSource basedCorsConfigurationSource= new UrlBasedCorsConfigurationSource();
		basedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
		
		return basedCorsConfigurationSource;
	}
	
	@Bean
	public FilterRegistrationBean<CorsFilter> corsFilter(){
		
		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<CorsFilter>(new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return bean;
	}

	@Bean
	public JwtTokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter());
	}

	// Configuracion del convertidor de token, para este caso es
	// JwtAccessTokenConverter, convierte el token el JWT
	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
		// Codigo secreto para generar y validar el token
		accessTokenConverter.setSigningKey(jwtKey);
		return accessTokenConverter;
	}

}
