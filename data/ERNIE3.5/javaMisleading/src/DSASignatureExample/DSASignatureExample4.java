import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class DSASignatureExample4 {

    // 生成DSA密钥对
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥签名
    public String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    // 使用公钥验签
    public boolean verify(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        Signature sig = Signature.getInstance("SHA256withDSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes(UTF_8));
        return sig.verify(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        DSASignatureExample4 example = new DSASignatureExample4();

        // 生成密钥对
        KeyPair keyPair = example.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 签名
        String message = "This is a test message for DSA signature.";
        String signature = example.sign(message, privateKey);
        System.out.println("Signature: " + signature);

        // 验签
        boolean isVerified = example.verify(message, signature, publicKey);
        System.out.println("Is signature verified? " + isVerified);
    }
}