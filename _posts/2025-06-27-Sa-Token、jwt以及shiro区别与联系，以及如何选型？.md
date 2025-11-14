### jwt

首先jwt可以把它理解为一个**无状态**的令牌协议，它包括三部分：

+ Header（头部）：标记令牌的类型，签名算法等。

  ```json
  {
      "alg":"HS256",  ---加密算法
      "type","JWT"  ---类型
  }
  ```

+ Payload（有效荷载）：包括携带的用户信息、jwt签发者、过期时间等信息

  ```json
  iss: jwt签发者
  sub: jwt所面向的用户
  aud: 接收jwt的一方
  exp: jwt的过期时间，这个过期时间必须要大于签发时间
  nbf: 定义在什么时间之前，该jwt都是不可用的.
  iat: jwt的签发时间
  jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
  ```

+ Signature（签名）：对Header和Payload这两部分数据通过secret（私钥）进行签名，防止Token被篡改

> jwt的定位是一个令牌格式协议，无状态存储，依赖令牌自验证。
>
> 而要组成完整的权限认证框架，还需自行实现权限体系

### jwt+shiro

由上述内容可知，**jwt**提供的是一种安全的、==无状态==的认证方式，但本身并不包含授权逻辑、会话管理之外的高级安全特性。

而**shiro**是一个全面的安全框架，除了认证外，还提供了==授权==、==会话管理==、==加密==等安全功能。

shiro下的认证方式如下：

1. 用户登录 → 后端自定义`Realm`域 → 用户名和密码的校验 → 产生`SessionId`为key的用户安全数据 → 交由shiro会话管理 → `SessionId`存入Redis → `SessionId`返回给前端

2. 请求带有`SessionId` → 后端自定义`Realm`域 → 交由会话管理 → 将传递过来的`SessionId`与Redis存储的比较 → 返回构造的安全数据（包含权限信息）

可以看出，它其实是一个==有状态==的服务。

但是在分布式场景下，存储和维护`SessionId`会更加复杂，试想每个用户登录时发给他一个`SessionId`，用户只需存储他自己的`SessionId`就好，而服务器需要存储每个用户的`SessionId`。同时在分布式的场景下，当用户之后带着他的`SessionId`被转发到另一台机器上，这样另一台机器也需要存储该用户的`SessionId`，就得做复制，无疑很浪费机器的资源。

因此，看中了jwt的无状态特性，我们结合jwt的无状态+天然的跨域优势，以及shiro强大的安全功能，强强结合。

**具体实现**

使用shiro+jwt的登录验证，主要配置以下内容：

+ `JwtToken`：token的对象信息，可以设置用户ID、密码等
+ `JwtRealm`：自定义验证服务，继承了`AuthorizingRealm`类
+ `JwtFilter`：自定义Filter过滤器，继承`AccessControlFilter`
+ `JwtUtil`：token的创建、解析、验证工具类
+ `ShiroConfig`：shiro的配置启动类
+ `AccessController`：请求到达的控制器

**`JwtToken`token信息**

token的实体类

```java
public class JwtToken implements AuthenticationToken {

    private String jwt;

    public JwtToken(String jwt) {
        this.jwt = jwt;
    }

    @Override
    public Object getPrincipal() {
        return jwt;  //账户
    }

    @Override
    public Object getCredentials() {
        return jwt;  //密码
    }

}
```

**`JwtRealm`验证配置**

```java
public class JwtRealm extends AuthorizingRealm {

    private static JwtUtil jwtUtil = new JwtUtil();

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String jwt = (String) token.getPrincipal();
        if (jwt == null) {
            throw new NullPointerException("jwtToken不允许为空");
        }
        // 判断 -- 验证处理
        if (!jwtUtil.isVerify(jwt)) {
            throw new UnknownAccountException();
        }
        // 可以获取username信息，并做一些处理
        String username = (String) jwtUtil.decode(jwt).get("username");
        return new SimpleAuthenticationInfo(jwt, jwt, "JwtRealm");
    }
}
```

**`JwtFilter`过滤器**

自定义的 Filter 在 `onAccessDenied()` 获取 request 请求的 token 入参信息，之后调用 `getSubject()` 进行验证处理

```java
public class JwtFilter extends AccessControlFilter {

    /**
     * 判断是否携带有效的 JwtToken
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return false;
    }

    /**
     * 返回结果为true表明登录通过
     */
    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        JwtToken jwtToken = new JwtToken(request.getParameter("token"));  //拿到请求里的token
        try {
            // 鉴权认证
            getSubject(servletRequest, servletResponse).login(jwtToken);
            return true;
        } catch (Exception e) {
            logger.error("鉴权认证失败", e);
            onLoginFail(servletResponse);
            return false;
        }
    }

    /**
     * 鉴权认证失败时默认返回 401 状态码
     */
    private void onLoginFail(ServletResponse response) throws IOException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse.getWriter().write("Auth Err!");
    }

}
```

**`ShiroConfig`启动配置**

设置过滤器和拦截处理，拦截指定的 `/verify` 方法。如果是 `/**` 就是拦截所有除了 `login`、`logout` 配置的其他方法

```java
@Configuration
public class ShiroConfig {

    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean() {
        ShiroFilterFactoryBean shiroFilter = new ShiroFilterFactoryBean();
        shiroFilter.setSecurityManager(securityManager());
        shiroFilter.setLoginUrl("/unauthenticated");
        shiroFilter.setUnauthorizedUrl("/unauthorized");
        // 添加jwt过滤器
        Map<String, Filter> filterMap = new HashMap<>();
        // 设置过滤器 -- \logout等不设置
        filterMap.put("anon", new AnonymousFilter());
        filterMap.put("jwt", new JwtFilter());
        filterMap.put("logout", new LogoutFilter());
        shiroFilter.setFilters(filterMap);
        // 拦截器，指定方法走哪个拦截器
        Map<String, String> filterRuleMap = new LinkedHashMap<>();
        filterRuleMap.put("/login", "anon");
        filterRuleMap.put("/logout", "logout");
        filterRuleMap.put("/verify", "jwt");  //verify走jwt拦截器
        shiroFilter.setFilterChainDefinitionMap(filterRuleMap);
        return shiroFilter;
    }
}
```

**`AccessController`请求到达的控制器**

```java
@RestController
public class AccessController {

    @RequestMapping("/authorize")
    public ResponseEntity<Map<String, String>> authorize(String username, String password) {
        Map<String, String> map = new HashMap<>();
        // 模拟账号和密码校验
        if (!"abc".equals(username) || !"123".equals(password)) {
            map.put("msg", "用户名密码错误");
            return ResponseEntity.ok(map);
        }
        // 校验通过生成token
        JwtUtil jwtUtil = new JwtUtil();
        Map<String, Object> chaim = new HashMap<>();
        chaim.put("username", username);
        String jwtToken = jwtUtil.encode(username, 60 * 60 * 1000, chaim);
        map.put("msg", "授权成功");
        map.put("token", jwtToken);
        // 返回token码
        return ResponseEntity.ok(map);
    }

    /**
     * http://localhost:8080/verify?token=
     */
    @RequestMapping("/verify")
    public ResponseEntity<String> verify(String token) {
        logger.info("验证 token：{}", token);
        return ResponseEntity.status(HttpStatus.OK).body("verify success!");
    }

    @RequestMapping("/success")
    public String success(){
        return "test success";
    }
}
```

### Sa-Token

Sa-Token 是一个**轻量级 Java 权限认证框架**，包括：登录认证、权限认证、单点登录、OAuth2.0、微服务鉴权。Sa-Token拥有开箱即用的API，也支持 JWT 作为令牌格式，并提供注解式的鉴权服务，简单易用。

> [dromara/Sa-Token: 一个轻量级 Java 权限认证框架，让鉴权变得简单、优雅！—— 登录认证、权限认证、分布式Session会话、微服务网关鉴权、单点登录、OAuth2.0 (github.com)](https://github.com/dromara/sa-token)

相比于shiro来说，Sa-Token的使用更加简便，能够很快速地搭建权限管理系统。shiro相对来说配置会更加复杂一点，比如认证器配置、授权器配置、Session管理配置等。

引入Sa-Token后，在登录时调用`StpUtil.login`方法，就能实现一次登录。这个过程中，Sa-Token 就会保存下登录的信息，如果对接了 Redis 就会保存在 Redis 上。

下一次用户在访问其它页面的时候，比如：

```java
@PostMapping("/order")
public Result<String> order(@Valid @RequestBody AParam aParam) {
    String userId = (String) StpUtil.getLoginId();
    // ...
}
```

就可以发现，这个接口并没有传入`userId`进来，因为有时候前端的参数是可以被篡改的，所以由服务端自己去Sa-Token中通过`StpUtil.getLoginId()`获取数据。

**具体实现**

**`SaTokenConfigure`全局配置**

```java
@Configuration
@Slf4j
public class SaTokenConfigure {

    @Bean
    public SaReactorFilter getSaReactorFilter() {
        return new SaReactorFilter()
                // 拦截地址
                .addInclude("/**")
                // 开放地址
                .addExclude("/favicon.ico")
                // 鉴权方法：每次访问进入
                .setAuth(obj -> {
                    // 登录校验 -- 拦截所有路由，排除不鉴权的页面
                    SaRouter.match("/**").notMatch("/auth/**", "/wxPay/**").check(r -> StpUtil.checkLogin());
                    // 权限认证 -- 不同模块, 校验不同权限
                    SaRouter.match("/admin/**", r -> StpUtil.checkRole(UserRole.ADMIN.name()));
                    SaRouter.match("/trade/**", r -> StpUtil.checkPermission(UserPermission.AUTH.name()));

                    SaRouter.match("/user/**", r -> StpUtil.checkPermissionOr(UserPermission.BASIC.name(), UserPermission.FROZEN.name()));
                    SaRouter.match("/order/**", r -> StpUtil.checkPermissionOr(UserPermission.BASIC.name(),UserPermission.FROZEN.name()));
                })
                // 异常处理方法：每次setAuth函数出现异常时进入
                .setError(this::getSaResult);
    }

    private SaResult getSaResult(Throwable throwable) {
        switch (throwable) {
            case NotLoginException notLoginException:
                log.error("请先登录");
                return SaResult.error("请先登录");
            case NotRoleException notRoleException:
                if (UserRole.ADMIN.name().equals(notRoleException.getRole())) {
                    log.error("请勿越权使用！");
                    return SaResult.error("请勿越权使用！");
                }
                log.error("您无权限进行此操作！");
                return SaResult.error("您无权限进行此操作！");
            case NotPermissionException notPermissionException:
                if (UserPermission.AUTH.name().equals(notPermissionException.getPermission())) {
                    log.error("请先完成实名认证！");
                    return SaResult.error("请先完成实名认证！");
                }
                log.error("您无权限进行此操作！");
                return SaResult.error("您无权限进行此操作！");
            default:
                return SaResult.error(throwable.getMessage());
        }
    }
}
```

**`StpInterfaceImpl`重写`StpInterface`接口，自定义权限认证**

```java
@Component
public class StpInterfaceImpl implements StpInterface {

    /**
     * 返回一个账号所拥有的权限码集合
     * @param loginId 登录id
     * @param loginType loginKey
     * @return
     */
    @Override
    public List<String> getPermissionList(Object loginId, String loginType) {
        UserInfo userInfo = (UserInfo) StpUtil.getSessionByLoginId(loginId).get((String) loginId);

        if (userInfo.getUserRole() == UserRole.ADMIN ||
            userInfo.getState().equals(UserStateEnum.AUTH.name()) ) {
            return List.of(UserPermission.BASIC.name(), UserPermission.AUTH.name());
        }

        if (userInfo.getState().equals(UserStateEnum.INIT.name())) {
            return List.of(UserPermission.BASIC.name());
        }

        if (userInfo.getState().equals(UserStateEnum.FROZEN.name())) {
            return List.of(UserPermission.FROZEN.name());
        }

        return List.of(UserPermission.NONE.name());
    }

    @Override
    public List<String> getRoleList(Object loginId, String loginType) {
        UserInfo userInfo = (UserInfo) StpUtil.getSessionByLoginId(loginId).get((String) loginId);
        if (userInfo.getUserRole() == UserRole.ADMIN) {
            return List.of(UserRole.ADMIN.name());
        }
        return List.of(UserRole.CUSTOMER.name());
    }
}
```

**`UserController`控制层登录接口**

```java
@RestController
public class UserController {

    // 登录接口
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        if ("admin".equals(username) && "123456".equals(password)) {
            StpUtil.login(10001); // 模拟用户 ID 为 10001
            return "登录成功，token=" + StpUtil.getTokenValue();
        }
        return "用户名或密码错误";
    }

    // 获取当前登录用户信息
    @GetMapping("/info")
    public String info() {
        StpUtil.checkLogin(); // 校验是否登录，未登录就会抛出异常
        return "当前会话用户ID：" + StpUtil.getLoginId();
    }

    // 只有 admin 权限用户才能访问
    @GetMapping("/admin")
    @SaCheckPermission("admin")
    public String adminPage() {
        return "管理员页面";
    }
}
```

**总结**

| 特性       | Sa-Token                    | Shiro                  | jwt                |
| ---------- | --------------------------- | ---------------------- | ------------------ |
| 类型       | 完整权限框架                | 通用权限框架           | 令牌标准（非框架） |
| 授权方式   | Session 或 Token（可选JWT） | Session为主，支持Token | Token（无状态）    |
| 登录认证   | 多种登录方式                | 多种登录方式           | 需配合框架使用     |
| 权限控制   | 注解+API控制                | 注解+API控制           | 不具备             |
| 单点登录   | 内置支持                    | 需集成                 | 需自建实现         |
| 会话管理   | 细粒度控制                  | 基于Session            | 无会话             |
| 微服务支持 | 天然支持                    | 弱（需扩展）           | 适合分布式         |
| 易用性     | 上手快、文档好              | 配置复杂               | 简单直观           |
| 底层机制   | 内置Token+缓存+会话         | 自定义Realm + 缓存     | 加密签名字符串     |
| 状态管理   | 有状态/无状态               | 有状态                 | 无状态             |

**shiro与Sa-Token如何选型**

| 场景                           | 推荐使用       |
| ------------------------------ | -------------- |
| 单体应用，追求稳定和拓展性     | Shiro          |
| 微服务、前后端分离系统         | Sa-Token + JWT |
| 高权限细粒度控制、用户行为管理 | Sa-Token       |