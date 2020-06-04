package com.mayikt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @Description security 两种模式
 * fromLogin 和   basic认证
 * @Author kuiwang
 * @Date 2020/6/4 13:44
 * @Version 1.0
 */
@SpringBootApplication
public class AppSecurity {
    public static void main(String[] args) {
        SpringApplication.run(AppSecurity.class, args);
    }
}