import java.security.*;
import java.util.Base64;

public class SignatureExample1 {
    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 要签名的消息
        String message = "Hello, this is a signed message!";

        // 使用私钥对消息进行签名
        String signature = signMessage(message, privateKey);
        System.out.println("Signature: " + signature);

        // 使用公钥验证签名
        boolean isVerified = verifySignature(message, signature, publicKey);
        System.out.println("Is the signature verified? " + isVerified);
    }

    // 生成密钥对的方法
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥对消息进行签名的方法
    public static String signMessage(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();
        return Base64.getEncoder().encodeToString(signedMessage);
    }

    // 使用公钥验证签名的方法
    public static boolean verifySignature(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes());
        byte[] signedMessage = Base64.getDecoder().decode(signature);
        return sig.verify(signedMessage);
    }
}