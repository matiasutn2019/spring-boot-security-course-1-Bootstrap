package com.example.demo.security;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // enables the @PreAuthorize of the methods
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.and()
//				.csrf().disable()
				.authorizeRequests()
				.antMatchers("/", "index", "/css/*", "/js/*").permitAll()
				.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name()) // Role based authentication
//				.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission()) // Permission based authentication, replace with @PreAuthorize at methods 
//				.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//				.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//				.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
				.anyRequest()
				.authenticated()
				.and()
				.formLogin() // Form based authentication
//				.httpBasic(); // Basic authentication
					.loginPage("/login").permitAll()
					.defaultSuccessUrl("/courses", true)
					.usernameParameter("username")
					.passwordParameter("password")
				.and()
//				.rememberMe(); // defaults to 2 weeks
				.rememberMe()
					.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(30))
					.rememberMeParameter("remember-me")
				.and()
				.logout()
					.logoutUrl("/logout")
//					.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // only if csrf is disable
					.clearAuthentication(true)
					.invalidateHttpSession(true)
					.deleteCookies("JSESSIONID", "remember-me")
					.logoutSuccessUrl("/login");
	}
	
	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		
		UserDetails annaSmithUser = User.builder()
				.username("annasmith")
				.password(passwordEncoder.encode("password"))
				// .roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
				.authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
				.build();
		
		UserDetails lindaUser = User.builder()
				.username("linda")
				.password(passwordEncoder.encode("password123"))
				// .roles(ApplicationUserRole.ADMIN.name()) // ROLE_ADMIN
				.authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
				.build();
		
		UserDetails tomUser = User.builder()
				.username("tom")
				.password(passwordEncoder.encode("password123"))
				// .roles(ApplicationUserRole.ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
				.authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
				.build();
		
		return new InMemoryUserDetailsManager(
				annaSmithUser,
				lindaUser,
				tomUser
		);		
	}
	
}