package com.redmaple.test;

import com.alibaba.fastjson.JSONObject;
import com.mayikt.utils.MD5Util;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.util.Base64Utils;

import java.util.Date;

/**
 * @Description 默认情况下JWT是未加密的，任何人都可以解读其内容，因此不要构建隐私信息字段，存放保密信息，以防止信息泄露。
 *  后端的jwt已经准备就绪，需要前后端配合处理
 *  一般存放的数据
 *  1、验证账号和密码 UserDetailsService
 *  2、账号和密码如果验证成功下，生成jwt返回客户端
 *  3、jwt中 payload 中存放那些内容（不敏感的信息），设置过期的时间短点
 *      userName，userImage，roles[]，showMember[]，...
 *
 * @Author redMaple-gi
 * @Date 2020/6/17 10:11
 * @Version 1.0
 */
public class JwtTest02 {
    public static String sign_key = "redMaple";

    public static void main(String[] args) {

        //加密
        JwtBuilder jwtBuilder = Jwts.builder()
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS256, sign_key);
        jwtBuilder.claim("name","若成风");
        jwtBuilder.claim("phone","1008611");
        String jwt = jwtBuilder.compact();
        System.out.println(jwt);

        // 解密
        Claims claims = Jwts.parser().setSigningKey(sign_key).parseClaimsJws(jwt).getBody();
        Object name = claims.get("name"); // claims 类似于map
        String s = claims.toString();
        System.out.println(s);

    }

}