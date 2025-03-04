import java.security.*;
import java.util.Base64;

public class ECDSASignatureExample3 {

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 要签名的消息
        String message = "这是一个待签名的消息";

        // 签名
        String signature = sign(message, privateKey);
        System.out.println("签名： " + signature);

        // 验证签名
        boolean isValid = verify(message, signature, publicKey);
        System.out.println("签名是否有效： " + isValid);
    }

    // 生成密钥对的方法
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    // 签名方法
    public static String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(message.getBytes());
        byte[] signatureBytes = ecdsaSign.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    // 验证签名方法
    public static boolean verify(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(message.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return ecdsaVerify.verify(signatureBytes);
    }
}