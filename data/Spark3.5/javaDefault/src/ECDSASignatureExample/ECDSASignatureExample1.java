import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 要签名的消息
        String message = "Hello, this is a message to be signed!";

        // 使用私钥对消息进行签名
        String signature = signMessage(privateKey, message);
        System.out.println("Signature: " + signature);

        // 使用公钥验证签名
        boolean isVerified = verifySignature(publicKey, message, signature);
        System.out.println("Is the signature verified? " + isVerified);
    }

    // 生成ECDSA密钥对
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥对消息进行签名
    public static String signMessage(PrivateKey privateKey, String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();
        return Base64.getEncoder().encodeToString(signedMessage);
    }

    // 使用公钥验证签名
    public static boolean verifySignature(PublicKey publicKey, String message, String signature) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256withECDSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(message.getBytes());
        byte[] decodedSignature = Base64.getDecoder().decode(signature);
        return signatureInstance.verify(decodedSignature);
    }
}