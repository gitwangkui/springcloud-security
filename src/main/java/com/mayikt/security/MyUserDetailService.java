package com.mayikt.security;

import com.mayikt.entity.Permission;
import com.mayikt.entity.User;
import com.mayikt.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * @Description 实现 security中的接口
 * @Author redMaple-gi
 * @Date 2020/6/10 11:37
 * @Version 1.0
 */
@Component
public class MyUserDetailService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 根据登录用户名查询用户信息
        User user = userMapper.findByUsername(username);
        // 根据用户查询用户对应的权限
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        List<Permission> permissionList = userMapper.findPermissionByUsername(username);
        permissionList.forEach(permission -> {
            authorities.add(new SimpleGrantedAuthority(permission.getPermTag()));
        });
        // 设置用户权限
        user.setAuthorities(authorities);
        return user;
    }
}