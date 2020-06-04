package com.mayikt.config;


import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Component;

/**
 * @Description
 * @Author kuiwang
 * @Date 2020/6/4 13:57
 * @Version 1.0
 */
@Component
@EnableWebSecurity  //开启WebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 配置 httpSecurity拦截信息
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        super.configure(http);
        http.authorizeRequests()
                .antMatchers("/**")
                .fullyAuthenticated()
                .and().httpBasic();

    }

    // 用户认证信息
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("123456")
                .authorities("addOrder");
    }

}