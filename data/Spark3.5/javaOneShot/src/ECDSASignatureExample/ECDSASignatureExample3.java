import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSASignatureExample3 {
    private static final String ALGORITHM = "ECDSA";
    private static final String CURVE = "secp256r1";
    private static final int KEY_SIZE = 256;

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 要签名的消息
        String message = "Hello, ECDSA!";

        // 签名
        String signature = sign(message, privateKey);
        System.out.println("签名： " + signature);

        // 验签
        boolean isVerified = verify(message, signature, publicKey);
        System.out.println("验签结果： " + isVerified);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(CURVE);
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();
        return Base64.getEncoder().encodeToString(signedMessage);
    }

    public static boolean verify(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(message.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return sig.verify(signatureBytes);
    }
}