package com.example.task.configuration;

import com.example.task.filter.JWTAuthenticationFilter;
import com.example.task.filter.JWTLoginFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    public void configureAuthentication(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(this.userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder());
    }

    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * DEV Security configuration
     */
    @Configuration
    @EnableWebSecurity
    @Order(1)
    public static class BasicSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        @Autowired
        private AuthenticationEntryPoint authEntryPoint;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable();

            http.authorizeRequests().anyRequest().authenticated();

            http.httpBasic().authenticationEntryPoint(authEntryPoint);
        }

        @Bean
        public BCryptPasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

            String password = "123";

            String encrytedPassword = this.passwordEncoder().encode(password);
            System.out.println("Encoded password of 123 = " + encrytedPassword);

            InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> //
                    mngConfig = auth.inMemoryAuthentication();

            UserDetails u1 = User.withUsername("John").password(encrytedPassword).roles("DEV").build();
            UserDetails u2 = User.withUsername("Kate").password(encrytedPassword).roles("DEV").build();

            mngConfig.withUser(u1);
            mngConfig.withUser(u2);
        }
    }

    /**
     * TEST security configuration
     */
    @Configuration
    @EnableWebSecurity
    @Order(2)
    public static class JWTSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable().authorizeRequests()
                    .antMatchers("/").permitAll() //
                    .antMatchers(HttpMethod.POST, "/login").permitAll()
                    .antMatchers(HttpMethod.GET, "/login").permitAll()
                    .antMatchers(HttpMethod.PUT, "/login").permitAll()
                    .antMatchers(HttpMethod.DELETE, "/login").permitAll()
                    // после аутентификации
                    .anyRequest().authenticated()
                    .and()
                    // JWTLoginFilter
                    .addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
                            UsernamePasswordAuthenticationFilter.class)
                    // JWTAuthenticationFilter
                    .addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        }

        @Bean
        public BCryptPasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {

            String password = "123";

            String encryptedPassword = this.passwordEncoder().encode(password);
            System.out.println("Encoded password of 123 = " + encryptedPassword);

            InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> //
                    mngConfig = auth.inMemoryAuthentication();

            UserDetails u1 = User.withUsername("Tom").password(encryptedPassword).roles("TEST").build();
            UserDetails u2 = User.withUsername("Marry").password(encryptedPassword).roles("TEST").build();

            mngConfig.withUser(u1);
            mngConfig.withUser(u2);
        }
    }
}