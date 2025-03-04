import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class RSASignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample2() throws NoSuchAlgorithmException {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 使用2048位密钥长度
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 使用私钥签名
    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    // 使用公钥验签
    public boolean verify(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            RSASignatureExample2 rsaExample = new RSASignatureExample2();

            // 原始消息
            String message = "Hello, RSA Signature Example!";

            // 生成签名
            String signature = rsaExample.sign(message);
            System.out.println("Signature: " + signature);

            // 验证签名
            boolean isValid = rsaExample.verify(message, signature);
            System.out.println("Signature Valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}