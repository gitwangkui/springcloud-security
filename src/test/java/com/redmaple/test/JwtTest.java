package com.redmaple.test;

import com.alibaba.fastjson.JSONObject;
import com.mayikt.utils.MD5Util;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Base64Utils;

/**
 * @Description 默认情况下JWT是未加密的，任何人都可以解读其内容，因此不要构建隐私信息字段，存放保密信息，以防止信息泄露。
 * @Author redMaple-gi
 * @Date 2020/6/17 10:11
 * @Version 1.0
 */
public class JwtTest {
    public static String saltVale = "redMaple";

    public static void main(String[] args) {
        // HEADER
        JSONObject header = new JSONObject();
        // 默认为HS256，只是转码，没有加密，相当于还是明文
        header.put("alg", "HS256");

        // PAYLOAD
        JSONObject payload = new JSONObject();
        payload.put("name", "若成风");
        payload.put("phone", "176****8522");

        String headerStr = header.toString();
        String headerBase64Str = Base64Utils.encodeToUrlSafeString(headerStr.getBytes());
        System.out.println("headerBase64Str: " + headerBase64Str);

        String payloadStr = payload.toString();
        String payloadBase64Str = Base64Utils.encodeToUrlSafeString(payloadStr.getBytes());
        System.out.println("payloadBase64Str: " + payloadBase64Str);

        // VERIFY SIGNATURE  签名值实际就是加密
        String verifySign = MD5Util.encode(headerStr+payloadStr);
        System.out.println("verifySign: " + verifySign);

        // 组合成jwt
        String jwt = headerBase64Str + "." + payloadBase64Str + "." + verifySign;
        System.out.println("jwt: " + jwt);


        // 开始解密
        String[] splits = jwt.split("\\."); // 这个 . 需要转义下
        String headerDecodeStr = new String(Base64Utils.decodeFromString(splits[0]));
        String payloadDecodeStr = new String(Base64Utils.decodeFromString(splits[1]));
        System.out.println("headerDecodeStr: " +headerDecodeStr +" \tpayloadDecodeStr: " +payloadDecodeStr );
        String newSign = MD5Util.encode(headerDecodeStr + payloadDecodeStr);
        // 安全，签名校验-->防止异常篡改参数
        System.out.println(newSign +"  解密后是否相等："+ newSign.equals(splits[2]));


    }

}