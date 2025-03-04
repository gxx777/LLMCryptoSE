import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class RSASignatureExample3 {

    // 生成RSA密钥对
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 使用足够大的密钥长度，例如2048位
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥签名消息
    public static String signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA"); // 使用安全的签名算法和哈希函数
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    // 使用公钥验签消息
    public static boolean verifySignature(String message, String signature, PublicKey publicKey) throws Exception {
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        Signature signatureToVerify = Signature.getInstance("SHA256withRSA");
        signatureToVerify.initVerify(publicKey);
        signatureToVerify.update(message.getBytes(StandardCharsets.UTF_8));
        return signatureToVerify.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            // 生成密钥对
            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // 消息内容
            String message = "This is a secret message.";

            // 签名消息
            String signature = signMessage(message, privateKey);
            System.out.println("Signature: " + signature);

            // 验签消息
            boolean isVerified = verifySignature(message, signature, publicKey);
            System.out.println("Signature Verified: " + isVerified);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}