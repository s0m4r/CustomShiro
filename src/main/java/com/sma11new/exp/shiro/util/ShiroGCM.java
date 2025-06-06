package com.sma11new.exp.shiro.util;

import cn.hutool.core.util.ArrayUtil;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.SimpleByteSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

/**
 * @ClassName: ShiroGCM
 * @Description: TODO
 * @Author: Summer
 * @Date: 2022/4/18 15:05
 * @Version: v1.0.0
 * @Description:
 **/
public class ShiroGCM implements EncryptInterface {

    @Override
    public byte[] getBytes(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = null;
        ObjectOutputStream objectOutputStream = null;
        byteArrayOutputStream = new ByteArrayOutputStream();
        objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.flush();
        return byteArrayOutputStream.toByteArray();
    }

    @Override
    public String encrypt(String key, byte[] objectBytes) {
        try {
            byte[] keyDecode = Base64.decode(key);
            AesCipherService cipherService = new AesCipherService();
            SimpleByteSource byteSource = (SimpleByteSource) cipherService.encrypt(objectBytes, keyDecode);
            return byteSource.toBase64();
        }catch (Exception e){
            e.printStackTrace();
        }

        return null;

    }

    @Override
    public String getName() {
        return "gcm";
    }

}
