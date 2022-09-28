package com.primus.springsecurityinmemory;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties
@EnableWebSecurity
public class SecurityConfig {

    // method name could be anything but return type is InMemoryUserDetailsManager

    @Bean
    protected InMemoryUserDetailsManager configAuthentication(){

        // users container
        List<UserDetails> users = new ArrayList<>();

        //admin authority container
        List<GrantedAuthority> admingrantedAuthorityList = new ArrayList<>();

        //adding admin role to admin authority container
        admingrantedAuthorityList.add(new SimpleGrantedAuthority("ADMIN"));

        //creating new user called admin
        //{noop} is added infront of password because we are not encoding the password
        UserDetails admin = new User("admin","{noop}admin",admingrantedAuthorityList);

        // added admin to users container
        users.add(admin);

        List<GrantedAuthority> empgrantedAuthorityList = new ArrayList<>();
        empgrantedAuthorityList.add(new SimpleGrantedAuthority("EMPLOYEE"));
        UserDetails emp = new User("emp","{noop}emp",empgrantedAuthorityList);
        users.add(emp);

        List<GrantedAuthority> mgrgrantedAuthorityList = new ArrayList<>();
        mgrgrantedAuthorityList.add(new SimpleGrantedAuthority("MANAGER"));
        UserDetails manager = new User("man","{noop}man",mgrgrantedAuthorityList);
        users.add(manager);

        return new InMemoryUserDetailsManager(users);
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        //declares which Page(URL) will have What access type
        http.authorizeRequests()
                .antMatchers("/home").permitAll()
                .antMatchers("/welcome").authenticated()
                .antMatchers("/admin").hasAuthority("ADMIN")
                .antMatchers("/emp").hasAuthority("EMPLOYEE")
                .antMatchers("/mgr").hasAuthority("MANAGER")
                .antMatchers("/common").hasAnyAuthority("EMPLOYEE","MANAGER")
                // Any other URLs which are not configured in above antMatchers
                // generally declared aunthenticated() in real time
                .anyRequest().authenticated()
                //Login Form Details
                .and()
                .formLogin()
                //after login default page is welcome
                .defaultSuccessUrl("/welcome", true)
                //Logout Form Details
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                //Exception Details
                .and()
                .exceptionHandling()
                .accessDeniedPage("/accessDenied")
                ;

        return http.build();
    }
}
