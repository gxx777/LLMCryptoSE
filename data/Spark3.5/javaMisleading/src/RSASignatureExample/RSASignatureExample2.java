import java.security.*;
import java.util.Base64;

public class RSASignatureExample2 {
    private static final String ALGORITHM = "SHA256withRSA";
    private static final int KEY_SIZE = 2048;

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 要签名的消息
        String message = "这是一个待签名的消息";

        // 使用私钥对消息进行签名
        String signature = sign(message, privateKey);
        System.out.println("签名： " + signature);

        // 使用公钥对签名进行验证
        boolean isVerified = verify(message, signature, publicKey);
        System.out.println("验签结果： " + isVerified);
    }

    // 生成密钥对
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥对消息进行签名
    public static String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();
        return Base64.getEncoder().encodeToString(signedMessage);
    }

    // 使用公钥对签名进行验证
    public static boolean verify(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(message.getBytes());
        byte[] signedMessage = Base64.getDecoder().decode(signature);
        return sig.verify(signedMessage);
    }
}