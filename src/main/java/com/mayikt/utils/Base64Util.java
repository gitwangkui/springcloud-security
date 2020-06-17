package com.mayikt.utils;

import com.alibaba.fastjson.JSONObject;

import java.io.IOException;
import java.util.Base64;

/**
 * @Author liuchao
 * @Date 2019/3/6 9:55
 * @Description
 */
public class Base64Util {

    public static String ENCODING_UTF_8 = "UTF-8";
    /** 解密
     * @Author: liuchao
     * @param str
     * @return
     */
    public static String decoder(String str) {
        try {
            return new String(Base64.getDecoder().decode(str), ENCODING_UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**先base64解密，得到json。再把json转换为object
     * @Author: liuchao
     * @param str
     * @return
     */
    public static <T> T decoderObject(String str,Class<T> classz) {
        return JSONObject.parseObject(decoder(str),classz);
    }


    /** 加密
     * @Author: liuchao
     * @param str
     * @return
     */
    public static String encoder(String str) {
        try {
            return new String(Base64.getEncoder().encode(str.getBytes()), ENCODING_UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**先base64加密，得到json。再把json转换为object
     * @Author: liuchao
     * @param str
     * @return
     */
    public static <T> T encoderObject(String str,Class<T> classz) {
        //return JSONObject.parseObject(decoder(str),classz);
        return JSONObject.parseObject(encoder(str), classz);
    }
}
