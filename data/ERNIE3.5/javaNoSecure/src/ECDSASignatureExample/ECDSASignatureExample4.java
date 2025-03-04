import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

public class ECDSASignatureExample4 {

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 原始消息
        String message = "Hello, ECDSA!";

        // 签名
        String signature = sign(message.getBytes(), privateKey);
        System.out.println("Signature: " + signature);

        // 验签
        boolean isValid = verify(message.getBytes(), signature, publicKey);
        System.out.println("Signature valid: " + isValid);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        return keyGen.generateKeyPair();
    }

    public static String sign(byte[] message, PrivateKey privateKey) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(message);
        byte[] signature = ecdsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(byte[] message, String signature, PublicKey publicKey) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(publicKey);
        ecdsa.update(message);
        byte[] decodedSignature = Base64.getDecoder().decode(signature);
        return ecdsa.verify(decodedSignature);
    }
}