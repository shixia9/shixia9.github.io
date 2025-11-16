---
categories: [Java, Mybatis]
tags: [java]
---

> 在一些项目中，有部分隐私数据如用户的姓名、身份证号等，这些都是非常敏感的个人隐私数据，如果明文直接存储到数据库中可能会有隐私泄露的隐患；例如当数据库遭到脱库时，就会造成严重的隐私泄露，因此需要考虑到在持久化用户信息时，如何做到用户敏感信息的加密存储。

Mybatis经常用来作为数据库持久层，因此使用Mybatis的`TypeHandler`来考虑用来解决该问题；`TypeHandler`其实就是个**字段类型处理器**，它可以被用来处理JavaType与JdbcType之间的转换问题。

例如在一个Java实体类当中，存在一个用户信息类`UserInfo`

```java
@Setter
@Getter
public class UserInfo extends BaseEntity {

    private Long id;

    // ...省略其它字段

    private Location location;

}
```

其中，存在一个类型为`Location`的字段，而location在数据库中的存储类型是`varchar`；在这里`TypeHandler`的作用就是在它们之间做一个类型转换，具体为：

1. 在使用字段类型处理器时，必须开启映射注解: `autoResultMap = true`
   ```java
    @TableName(value = "user_info",autoResultMap = true)
   ```
   如果有自定义sql的话就无效，需要在xml定义的`resultMap`进行配置`TypeHandler`
   ```xml
   <resultMap id="BaseResultMap" type="com.atom.ai.tennessee.user.domain.entity.UserInfo">
        <result property="id" column="ID"/>
        <!-- ...省略其它字段 -->
        <result property="location" column="LOCATION" typeHandler="com.baomidou.mybatisplus.extension.handlers.JacksonTypeHandler"/>
    </resultMap>
   ```
2. 定义好了`TypeHandler`之后，就需要把他注册到需要进行转换的字段中；通过 `@TableField`注解将`FastjsonTypeHandler`这个类型处理器快速注入到mybatis容器中
   ```java
    @Setter
    @Getter
    @TableName(value = "user_info",autoResultMap = true)
    public class UserInfo extends BaseEntity {

        private Long id;

        // ...省略其它字段

        @TableField(typeHandler = JacksonTypeHandler.class)
        private Location location;

    }
    ```

因此，鉴于`TypeHandler`在JdbcType与JavaType之间的桥梁作用，就可以通过自定义`TypeHandler`做数据库当中一些敏感字段的加解密，具体步骤可考虑为：

1. 创建一个加解密的工具类，实现具体的加解密算法
2. 实现自定义`TypeHandler`，在这个类中编写加解密逻辑
3. 在具体需要进行脱敏的字段上使用该处理类，或者在对应的MyBatis配置文件中注册自定义的`TypeHandler`

## 创建加解密工具类

定义一个工具类实现GCM模式的AES加解密

> **为什么使用GCM模式的AES加密**
> + 认证加密一体：无需额外计算 MAC（消息认证码），加密过程同时生成认证标签，解密时自动校验内容完整性
> + 并行计算：加密和解密都支持并行处理，性能优于 CBC 等模式
> + 无需填充：属于流加密模式的变种，对任意长度数据无需填充
> + 初始化向量（IV）灵活性：推荐使用12字节IV，相同密钥下IV不重复即可保证安全性

GCM需要：
+ AES密钥：使用256位AES密钥
+ 随机IV：确保即使多次用同一密钥加密相同数据，加密后的数据也是唯一的

```java
public class AESGCMUtil {
    // 加密算法及模式
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    // 密钥长度：256
    private static final int KEY_SIZE = 256;
    // IV长度：12字节
    private static final int GCM_IV_LENGTH = 12;
    // 认证标签长度：128位
    private static final int GCM_TAG_LENGTH = 128;

    /**
     * 生成AES密钥
     * @return Base64编码的密钥
     * @throws NoSuchAlgorithmException 算法不支持异常
     */
    public static String generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE, new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * 生成随机IV
     * @return Base64编码的IV
     */
    public static String generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    /**
     * 加密
     * @param content 待加密内容
     * @param key Base64编码的密钥
     * @param iv Base64编码的IV
     * @return 加密结果
     */
    public static String encrypt(String content, String key, String iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // 解码密钥和IV
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] ivBytes = Base64.getDecoder().decode(iv);

        // 初始化密钥和GCM参数
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);

        // 加密模式初始化
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        // 执行加密（GCM模式无需填充，直接加密）
        byte[] encrypted = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 解密
     * @param encryptedContent Base64编码的加密内容
     * @param key Base64编码的密钥
     * @param iv Base64编码的IV
     * @return 解密后的明文
     * @throws BadPaddingException 若认证失败会抛出此异常
     */
    public static String decrypt(String encryptedContent, String key, String iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // 解码密钥、IV和加密内容
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] ivBytes = Base64.getDecoder().decode(iv);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedContent);

        // 初始化解密参数
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);

        // 解密模式初始化
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        // 执行解密
        byte[] decrypted = cipher.doFinal(encryptedBytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
```

**或者**

直接使用Hutool中提供的AES算法

```java
public class AesUtil {

    private static String key = "uTfe6WtWICU/6rk0Gr7qKrAvHaRvQj+HRaHKvSe9UJI=";
    private static AES aes = SecureUtil.aes(Base64.getDecoder().decode(key));

    public static String encrypt(String content) {
        //判空修改
        if (StringUtils.isBlank(content)) {
            return content;
        }
        return aes.encryptHex(content);
    }

    public static String decrypt(String content) {
        //判空修改
        if (StringUtils.isBlank(content)) {
            return content;
        }
        return aes.decryptStr(content);
    }
}
```

## 自定义TypeHandler

需要自定义一个`TypeHandler`来实现加解密的逻辑，通过实现`BaseTypeHandler`接口，重写它的`setNonNullParameter`等方法，实现对Java字段的自定义操作

```java
/**
 * AES加密类型处理器
 */
public class AesEncryptTypeHandler extends BaseTypeHandler<String> {
    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, String parameter, JdbcType jdbcType) throws SQLException {
        // 使用自定义加密方法进行加密
        ps.setString(i, encrypt(parameter));
    }

    @Override
    public String getNullableResult(ResultSet rs, String columnName) throws SQLException {
        String encrypted = rs.getString(columnName);
        return encrypted == null ? null : decrypt(encrypted);
    }

    @Override
    public String getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        String encrypted = rs.getString(columnIndex);
        return encrypted == null ? null : decrypt(encrypted);
    }

    @Override
    public String getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        String encrypted = cs.getString(columnIndex);
        return encrypted == null ? null : decrypt(encrypted);
    }

    /**
     * 加密方法
     * @param data
     * @return
     */
    private String encrypt(String data) {
        return AesUtil.encrypt(data);
    }

    /**
     * 解密方法
     * @param data
     * @return
     */
    private String decrypt(String data) {
        return AesUtil.decrypt(data);
    }
}
```

## 注册TypeHandler

使用`@TableField(typeHandler = EncryptDecryptTypeHandler.class)`注解，在使用MyBatisPlus时指定某个字段的TypeHandler，就可以实现特定字段的加解密

```java
// 真实姓名
@TableField(typeHandler = AESEncryptTypeHandler.class)
private String name;
// 身份证
@TableField(typeHandler = AESEncryptTypeHandler.class)
private String idCard;
```

在为Java字段添加上注解后，MyBatisPlus会在该字段进行读写操作时自动调用指定的TypeHandler