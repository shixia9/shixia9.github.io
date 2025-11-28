---
categories: [Java, Mybatis]
tags: [java, mybatis]
---

## 前言
Mybatis的插件(plugin)机制实际上是通过**动态代理**实现的，具体为在SQL执行的关键点，例如执行查询、更新、插入时，拦截操作并增强功能

拦截器拦截的类型包括：

+ `Executor`：负责执行CURD操作；
+ `ParameterHandler`：负责处理SQL语句当中的参数；
+ `ResultSetHandler`：负责处理结果集；
+ `StatementHandler`：负责处理SQL语句。

类似于切面，当拦截点的方法被调用时，Mybatis会先调用插件的`intercept`方法进行逻辑的嵌入，它提供了一个灵活的拦截功能

```java
@Intercepts({
        @Signature(type = Executor.class, method = "update", args = {MappedStatement.class, Object.class}),
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class})
})
public class XxxInterceptor implements Interceptor {
    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        // ...
    }
}
```

根据定义的`@Signature`当中的`type`以及`method`，可以去拦截

| 拦截点                            | 说明                         |
| ------------------------------ | -------------------------- |
| `Executor.update`                | `INSERT / UPDATE / DELETE` |
| `Executor.query`                 | 查询 SQL                     |
| `ParameterHandler.setParameters` | SQL 参数绑定阶段                 |
| `StatementHandler.prepare`       | SQL 预编译阶段                  |

通过 MyBatis 的插件的拦截机制，就可以轻松实现 SQL 性能监控，具体要拦截：

+ `Executor.update`
+ `Executor.query`

这样就能在 SQL 执行前后做耗时统计

## 实现
首先创建插件类`SqlPerformanceInterceptor`，它实现了`Interceptor`接口；重写拦截方法`intercept()`，这是插件的核心，所有被拦截的方法最终都会进入这里；它做了包括：

1. 取出带`?`的原始SQL模板
2. 取出参数对象
3. 去掉SQL中多余空格，使SQL更易读
4. 执行SQL
5. 计算SQL执行耗时
6. 判断慢查询，输出日志

```java
@Override
public Object intercept(Invocation invocation) throws Throwable {
    // 获取方法入参
    Object[] args = invocation.getArgs();
    MappedStatement mappedStatement = (MappedStatement) args[0];
    Object parameter = args.length > 1 ? args[1] : null;
    BoundSql boundSql = mappedStatement.getBoundSql(parameter);
    String rawSql = boundSql.getSql();
    if (rawSql == null) {
        rawSql = "";
    }
    String sql = MULTI_SPACES.matcher(rawSql).replaceAll(" ").trim();
    long start = System.nanoTime();
    Object result;
    try {
        result = invocation.proceed();
    } catch (Throwable throwable) {
        long endEx = System.nanoTime();
        long costMsEx = Math.max(0, (endEx - start) / 1_000_000);
        // 在异常场景也打印
        logger.warn("[mybatis-sql] SQL ID: {} | FAILED | cost={} ms | sql={}", mappedStatement.getId(), costMsEx, buildSqlWithParameters(sql, boundSql));
        throw throwable;
    }
    long end = System.nanoTime();
    long costMs = Math.max(0, (end - start) / 1_000_000);
    // 若慢查询阈值 <=0 则打印所有；否则只打印耗时大于阈值的
    if (slowSqlMillis <= 0 || costMs >= slowSqlMillis) {
        logger.info("[mybatis-sql] SQL ID: {} | cost={} ms | sql={}", mappedStatement.getId(), costMs, buildSqlWithParameters(sql, boundSql));
    }
    return result;
}
```

其次，实现它的`plugin()`方法，MyBatis通过这个方法来创建代理对象，否则拦截逻辑无法生效

```java
@Override
public Object plugin(Object target) {
    return Plugin.wrap(target, this);
}
```

`setProperties()`方法用来接收外部配置，比方说当MyBatis配置中写

```xml
<plugin interceptor="xxx.SqlPerformanceInterceptor">
    <property name="slowSqlMillis" value="200" />
</plugin>
```

这里会读取参数 200，覆盖默认的100ms；或者通过配置一个`MybatisConfig`配置类去读取`application.yml`当中的配置，用新的配置去覆盖默认的值

```java
// 慢查询阈值（毫秒）：<= 0 表示全部打印
private long slowSqlMillis = 100;

@Override
public void setProperties(Properties properties) {
    String slow = properties.getProperty("slowSqlMillis");
    if (slow != null) {
        try {
            this.slowSqlMillis = Long.parseLong(slow);
        } catch (NumberFormatException ignore) {
        }
    }
}
```

## 完整代码

```java
package com.atom.ai.infrastructure.interceptor;

import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.SystemMetaObject;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.regex.Pattern;

/**
 * @author at0m1c
 * @description 统计 SQL 执行耗时并打印到日志
 */
@Intercepts({
        @Signature(type = Executor.class, method = "update", args = {MappedStatement.class, Object.class}),
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class})
})
public class SqlPerformanceInterceptor implements Interceptor {

    private static final Logger logger = LoggerFactory.getLogger(SqlPerformanceInterceptor.class);

    // 慢查询阈值（毫秒）：<= 0 表示全部打印
    private long slowSqlMillis = 100;

    private static final Pattern MULTI_SPACES = Pattern.compile("\\s+");

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        // 获取方法入参
        Object[] args = invocation.getArgs();
        MappedStatement mappedStatement = (MappedStatement) args[0];
        Object parameter = args.length > 1 ? args[1] : null;
        BoundSql boundSql = mappedStatement.getBoundSql(parameter);
        String rawSql = boundSql.getSql();
        if (rawSql == null) {
            rawSql = "";
        }
        String sql = MULTI_SPACES.matcher(rawSql).replaceAll(" ").trim();
        long start = System.nanoTime();
        Object result;
        try {
            result = invocation.proceed();
        } catch (Throwable throwable) {
            long endEx = System.nanoTime();
            long costMsEx = Math.max(0, (endEx - start) / 1_000_000);
            // 在异常场景也打印
            logger.warn("[mybatis-sql] SQL ID: {} | FAILED | cost={} ms | sql={}", mappedStatement.getId(), costMsEx, buildSqlWithParameters(sql, boundSql));
            throw throwable;
        }
        long end = System.nanoTime();
        long costMs = Math.max(0, (end - start) / 1_000_000);
        // 若慢查询阈值 <=0 则打印所有；否则只打印耗时大于阈值的
        if (slowSqlMillis <= 0 || costMs >= slowSqlMillis) {
            logger.info("[mybatis-sql] SQL ID: {} | cost={} ms | sql={}", mappedStatement.getId(), costMs, buildSqlWithParameters(sql, boundSql));
        }
        return result;
    }

    /**
     * 将 SQL 中的 ? 用参数值逐个替换
     * @param sql
     * @param boundSql
     * @return
     */
    private String buildSqlWithParameters(String sql, BoundSql boundSql) {
        Object parameterObject = boundSql.getParameterObject();
        List<ParameterMapping> parameterMappings = boundSql.getParameterMappings();
        if (parameterMappings == null || parameterMappings.isEmpty() || parameterObject == null) {
            return sql;
        }
        // 先尝试从 additionalParameters 中取
        Map<String, Object> additionalParameters = boundSql.getAdditionalParameters();
        String parsedSql = sql;
        Object paramObject = parameterObject;
        MetaObject metaObject = SystemMetaObject.forObject(paramObject);
        for (ParameterMapping mapping : parameterMappings) {
            String propName = mapping.getProperty();
            Object value = null;
            // 优先从 additionalParameters
            if (additionalParameters.containsKey(propName)) {
                value = additionalParameters.get(propName);
            } else if (metaObject != null && metaObject.hasGetter(propName)) {
                value = metaObject.getValue(propName);
            } else {
                // 可能 paramObject 是基本类型或直接就是参数
                if (!isComplexObject(paramObject)) {
                    value = paramObject;
                } else {
                    // 尝试通过 reflection 取字段
                    try {
                        Field field = paramObject.getClass().getDeclaredField(propName);
                        field.setAccessible(true);
                        value = field.get(paramObject);
                    } catch (Exception e) {
                        value = null;
                    }
                }
            }
            String valueStr = formatParameterValue(value);
            // 使用正则替换第一个问号
            parsedSql = replaceFirstQuestionMark(parsedSql, valueStr);
        }
        return parsedSql;
    }

    private boolean isComplexObject(Object o) {
        if (o == null) return false;
        Class<?> clazz = o.getClass();
        return !(clazz.isPrimitive() || clazz == String.class
                || Number.class.isAssignableFrom(clazz) || Date.class.isAssignableFrom(clazz)
                || clazz.isArray());
    }

    private String replaceFirstQuestionMark(String sql, String replacement) {
        // 找到第一个问号并替换
        int idx = sql.indexOf("?");
        if (idx < 0) return sql;
        StringBuilder sb = new StringBuilder();
        sb.append(sql, 0, idx);
        sb.append(replacement);
        sb.append(sql.substring(idx + 1));
        return sb.toString();
    }

    private String formatParameterValue(Object obj) {
        if (obj == null) return "NULL";
        if (obj instanceof String) {
            return "'" + obj.toString().replace("'", "''") + "'";
        }
        if (obj instanceof Date) {
            // 格式化日期
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            return "'" + sdf.format((Date) obj) + "'";
        }
        if (obj instanceof Timestamp) {
            return "'" + obj.toString() + "'";
        }
        if (obj.getClass().isArray()) {
            int len = Array.getLength(obj);
            StringJoiner sj = new StringJoiner(", ", "(", ")");
            for (int i = 0; i < len; i++) {
                sj.add(formatParameterValue(Array.get(obj, i)));
            }
            return sj.toString();
        }
        if (obj instanceof Collection) {
            Collection<?> collection = (Collection<?>) obj;
            StringJoiner sj = new StringJoiner(", ", "(", ")");
            for (Object o : collection) {
                sj.add(formatParameterValue(o));
            }
            return sj.toString();
        }
        // 默认数字或其他类型
        if (obj instanceof Number || obj instanceof Boolean) {
            return String.valueOf(obj);
        }
        return "'" + obj.toString().replace("'", "''") + "'";
    }

    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    /**
     * 可通过 properties 配置 slowSqlMillis（单位 ms），如：slowSqlMillis=200
     * @param properties properties
     */
    @Override
    public void setProperties(Properties properties) {
        String slow = properties.getProperty("slowSqlMillis");
        if (slow != null) {
            try {
                this.slowSqlMillis = Long.parseLong(slow);
            } catch (NumberFormatException ignore) {
            }
        }
    }
}
```

