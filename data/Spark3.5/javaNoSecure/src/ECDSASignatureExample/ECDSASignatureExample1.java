import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class ECDSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 要签名的消息
        String message = "Hello, ECDSA!";

        // 使用私钥对消息进行签名
        byte[] signature = signMessage(privateKey, message);
        System.out.println("签名： " + Arrays.toString(signature));

        // 使用公钥验证签名
        boolean isVerified = verifySignature(publicKey, message, signature);
        System.out.println("验签结果： " + isVerified);
    }

    // 生成ECDSA密钥对
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥对消息进行签名
    public static byte[] signMessage(PrivateKey privateKey, String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    // 使用公钥验证签名
    public static boolean verifySignature(PublicKey publicKey, String message, byte[] signature) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256withECDSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(message.getBytes());
        return signatureInstance.verify(signature);
    }
}