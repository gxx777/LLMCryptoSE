import java.security.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ECDSASignatureExample2 {

    // 生成ECDSA密钥对
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // 使用256位密钥长度
        return keyGen.generateKeyPair();
    }

    // 使用私钥进行签名
    public static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    // 使用公钥进行验签
    public static boolean verify(String message, String signature, PublicKey publicKey) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256withECDSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return signatureInstance.verify(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 原始消息
        String message = "Hello, ECDSA!";

        // 签名
        String signature = sign(message, privateKey);
        System.out.println("Signature: " + signature);

        // 验签
        boolean isVerified = verify(message, signature, publicKey);
        System.out.println("Signature Verified: " + isVerified);
    }
}