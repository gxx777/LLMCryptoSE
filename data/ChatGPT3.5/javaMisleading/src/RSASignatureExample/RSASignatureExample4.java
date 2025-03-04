import java.security.*;
import java.util.Base64;

public class RSASignatureExample4 {

    public static void main(String[] args) throws Exception {
        String message = "Hello, world!";
        
        // 生成RSA密钥对
        KeyPair keyPair = generateRSAKeyPair();
        
        // 使用私钥对消息进行签名
        String signature = signMessage(message, keyPair.getPrivate());
        System.out.println("Signature: " + signature);
        
        // 使用公钥对签名进行验签
        boolean verified = verifySignature(message, signature, keyPair.getPublic());
        System.out.println("Signature verified: " + verified);
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static String signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private static boolean verifySignature(String message, String signature, PublicKey publicKey) throws Exception {
        Signature verifiedSignature = Signature.getInstance("SHA256withRSA");
        verifiedSignature.initVerify(publicKey);
        verifiedSignature.update(message.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return verifiedSignature.verify(signatureBytes);
    }
}