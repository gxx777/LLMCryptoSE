import java.security.*;
import java.util.Base64;

public class RSASignatureExample2 {
    private static final int KEY_SIZE = 2048;
    private static final String ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 要签名的消息
        String message = "Hello, world!";

        // 使用私钥对消息进行签名
        String signature = sign(message, privateKey);
        System.out.println("签名： " + signature);

        // 使用公钥验证签名
        boolean isVerified = verify(message, signature, publicKey);
        System.out.println("验签结果： " + isVerified);
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();
        return Base64.getEncoder().encodeToString(signedMessage);
    }

    private static boolean verify(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(message.getBytes());
        byte[] decodedSignature = Base64.getDecoder().decode(signature);
        return sig.verify(decodedSignature);
    }
}