package com.mayikt.config;

import com.mayikt.utils.MD5Util;
import com.mayikt.entity.Permission;
import com.mayikt.handler.MyAuthenticationFailureHandler;
import com.mayikt.handler.MyAuthenticationSuccessHandler;
import com.mayikt.mapper.PermissionMapper;
import com.mayikt.security.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @Description 改为动态的，从数据库读读取数据
 * @Author kuiwang
 * @Date 2020/6/4 13:57
 * @Version 1.0
 */
@Component
//开启WebSecurity
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSuccessHandler successHandler;
    @Autowired
    private MyAuthenticationFailureHandler failureHandler;
    @Autowired
    private MyUserDetailService myUserDetailService;
    @Autowired
    private PermissionMapper permissionMapper;

    // 配置 httpSecurity拦截信息
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry expressionInterceptUrlRegistry = http.authorizeRequests();
        List<Permission> permissionList = permissionMapper.findAllPermission();
        permissionList.forEach(p -> {
            expressionInterceptUrlRegistry.antMatchers(p.getUrl()).hasAnyAuthority(p.getPermTag());
        });

        expressionInterceptUrlRegistry.antMatchers("/login").permitAll()
                // .httpBasic()模式弹窗登录;  .formLogin()模式页面登录
                .antMatchers("/**").fullyAuthenticated().and().formLogin()
                // 指定登录页面
                .loginPage("/login").successHandler(successHandler).failureHandler(failureHandler).and().csrf().disable();

    }

    /**
     * 用户认证信息
      */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailService).passwordEncoder(new PasswordEncoder() {
            // 对页面传入的参数加密处理
            @Override
            public String encode(CharSequence rawPassword) {
                String encodeRawPassword = MD5Util.encode((String) rawPassword);
                return encodeRawPassword;
            }
            // 页面输入的rawPassword，  数据库里面保存的encodedPassword
            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                System.out.println("=====rawPassword: "+rawPassword+", encodedPassword: "+encodedPassword);
                String encodeRawPassword = this.encode(rawPassword);
                encodedPassword=encodedPassword.replace("\r\n", "");
                return encodeRawPassword.equals(encodedPassword);
            }
        });

    }

}