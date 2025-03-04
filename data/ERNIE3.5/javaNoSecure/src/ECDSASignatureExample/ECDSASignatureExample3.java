import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSASignatureExample3 {

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 原始消息
        String message = "This is a test message for ECDSA signature.";

        // 签名
        String signature = sign(message, privateKey);
        System.out.println("Signature: " + signature);

        // 验签
        boolean isValid = verify(message, signature, publicKey);
        System.out.println("Signature valid: " + isValid);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // 创建ECDSA密钥对生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1"));

        // 生成密钥对
        return keyPairGenerator.generateKeyPair();
    }

    public static String sign(String message, PrivateKey privateKey) throws Exception {
        // 获取签名算法实例
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);

        // 更新消息内容
        signature.update(message.getBytes(StandardCharsets.UTF_8));

        // 生成签名
        byte[] signatureBytes = signature.sign();

        // 将签名转换为Base64字符串
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public static boolean verify(String message, String signature, PublicKey publicKey) throws Exception {
        // 解码Base64签名
        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        // 获取签名算法实例
        Signature signatureVerifier = Signature.getInstance("SHA256withECDSA");
        signatureVerifier.initVerify(publicKey);

        // 更新消息内容
        signatureVerifier.update(message.getBytes(StandardCharsets.UTF_8));

        // 验证签名
        return signatureVerifier.verify(signatureBytes);
    }
}