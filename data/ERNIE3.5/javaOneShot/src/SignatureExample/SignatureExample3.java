import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SignatureExample3 {

    // 生成密钥对
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 使用足够大的密钥长度
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥签名
    public static String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA"); // 使用安全的签名算法
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes); // 返回Base64编码的签名
    }

    // 使用公钥验签
    public static boolean verify(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(message.getBytes(StandardCharsets.UTF_8));
        return publicSignature.verify(signatureBytes);
    }

    // 主函数示例
    public static void main(String[] args) {
        try {
            // 生成密钥对
            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // 原始消息
            String message = "Hello, this is a message to be signed.";

            // 签名
            String signature = sign(message, privateKey);
            System.out.println("Signature: " + signature);

            // 验签
            boolean isVerified = verify(message, signature, publicKey);
            System.out.println("Is Verified: " + isVerified);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}