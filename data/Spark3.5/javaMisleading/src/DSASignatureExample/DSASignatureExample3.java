import java.security.*;
import java.util.Base64;

public class DSASignatureExample3 {
    private static final int KEY_SIZE = 1024;

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 要签名的消息
        String message = "这是一个待签名的消息";

        // 使用私钥对消息进行签名
        byte[] signature = signMessage(message, privateKey);

        // 使用公钥对签名进行验证
        boolean isVerified = verifySignature(message, signature, publicKey);

        System.out.println("签名验证结果： " + (isVerified ? "成功" : "失败"));
    }

    // 生成密钥对的方法
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥对消息进行签名的方法
    public static byte[] signMessage(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    // 使用公钥对签名进行验证的方法
    public static boolean verifySignature(String message, byte[] signatureBytes, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }
}