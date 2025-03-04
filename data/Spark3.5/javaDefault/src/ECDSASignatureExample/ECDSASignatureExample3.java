import java.security.*;
import java.util.Base64;

public class ECDSASignatureExample3 {

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 要签名的消息
        String message = "Hello, this is a message to be signed using ECDSA!";

        // 使用私钥对消息进行签名
        String signature = signMessage(privateKey, message);
        System.out.println("Signature: " + signature);

        // 使用公钥验证签名
        boolean isVerified = verifySignature(publicKey, message, signature);
        System.out.println("Is the signature verified? " + isVerified);
    }

    // 生成ECDSA密钥对
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥对消息进行签名
    public static String signMessage(PrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(message.getBytes());
        byte[] signatureBytes = ecdsaSign.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    // 使用公钥验证签名
    public static boolean verifySignature(PublicKey publicKey, String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(message.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return ecdsaVerify.verify(signatureBytes);
    }
}