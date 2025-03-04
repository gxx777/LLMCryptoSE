import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSASignatureExample2 {

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 要签名的消息
        String message = "Hello, ECDSA!";

        // 签名
        String signature = sign(message, privateKey);
        System.out.println("签名： " + signature);

        // 验签
        boolean isVerified = verify(message, signature, publicKey);
        System.out.println("验签结果： " + isVerified);
    }

    // 生成密钥对
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    // 签名
    public static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();
        return Base64.getEncoder().encodeToString(signedMessage);
    }

    // 验签
    public static boolean verify(String message, String signature, PublicKey publicKey) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256withECDSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(message.getBytes());
        byte[] signedMessage = Base64.getDecoder().decode(signature);
        return signatureInstance.verify(signedMessage);
    }
}