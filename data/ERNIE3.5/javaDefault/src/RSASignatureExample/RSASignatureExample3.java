import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class RSASignatureExample3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample3() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 使用2048位密钥长度
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public boolean verify(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        Signature signatureInstance = Signature.getInstance("SHA256withRSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(message.getBytes(StandardCharsets.UTF_8));
        return signatureInstance.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            RSASignatureExample3 rsaExample = new RSASignatureExample3();

            String message = "Hello, RSA!";
            String signature = rsaExample.sign(message);
            System.out.println("Signature: " + signature);

            boolean isValid = rsaExample.verify(message, signature);
            System.out.println("Signature is valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}