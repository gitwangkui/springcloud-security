package com.mayikt.config;


import com.mayikt.handler.MyAuthenticationFailureHandler;
import com.mayikt.handler.MyAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @Description
 * @Author kuiwang
 * @Date 2020/6/4 13:57
 * @Version 1.0
 */
//@Component
//@EnableWebSecurity  //开启WebSecurity
public class SecurityConfig0 extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSuccessHandler successHandler;
    @Autowired
    private MyAuthenticationFailureHandler failureHandler;


    // 配置 httpSecurity拦截信息
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // .httpBasic()模式，弹窗登录;  .formLogin() 默认页面登录
        //http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().httpBasic();

        http.authorizeRequests()
                .antMatchers("/showOrder").hasAnyAuthority("showOrder")
                .antMatchers("/addOrder").hasAnyAuthority("addOrder")
                .antMatchers("/updateOrder").hasAnyAuthority("updateOrder")
                .antMatchers("/deleteOrder").hasAnyAuthority("deleteOrder")
                .antMatchers("/login").permitAll()
                // 开启页面登录formLogin()
                .antMatchers("/**").fullyAuthenticated().and().formLogin()
                // 设置自己的登录页面且关闭csrf
                //.loginPage("/login").and().csrf().disable();

                // 设置认证成功或失败的处理，比如进入一个指定的错误页面或者处理
                .loginPage("/login").successHandler(successHandler).failureHandler(failureHandler).and().csrf().disable();
    }

    /**
     * 用户认证信息
      */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 添加 redMaple账号，表示只有查看和添加订单的权限
        auth.inMemoryAuthentication().withUser("redMaple").password("123456")
                .authorities("showOrder","addOrder");
        // 添加 admin 账号, 目前用所有的权限
        auth.inMemoryAuthentication().withUser("admin").password("123456")
                .authorities("showOrder","addOrder","updateOrder","deleteOrder");
    }

    /**
     *  SpringBoot2.0抛弃了原来的NoOpPasswordEncoder，要求用户保存的密码必须要使用加密算法后存储，
     *  在登录验证的时候Security会将获得的密码在进行编码后再和数据库中加密后的密码进行对比
     * @return
     */
    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }


}