package com.concretepage.config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled=true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private MyAppUserDetailsService myAppUserDetailsService;	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/app/secure/**").hasAnyRole("ADMIN","USER")
		.and().formLogin()  //login configuration
        .loginPage("/app/login") // login page
        .loginProcessingUrl("/app-login") // submit "action" in login form : custom-login.html
        .usernameParameter("app_username") // user "name" field in custom login form
        .passwordParameter("app_password") // password "name" field in custom login form
        .defaultSuccessUrl("/app/secure/article-details")	
		.and().logout()    //logout configuration
		.logoutUrl("/app-logout") // Submit Action in the form : articles
		.logoutSuccessUrl("/app/login") // route to login page
		.and().exceptionHandling() //exception handling configuration
		.accessDeniedPage("/app/error");
	} 
    
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    	BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        auth.userDetailsService(myAppUserDetailsService).passwordEncoder(passwordEncoder);
	}
}