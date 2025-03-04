import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSASignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECDSASignatureExample2() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String signMessage(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = ecdsa.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public boolean verifySignature(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(publicKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return ecdsa.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            ECDSASignatureExample2 example = new ECDSASignatureExample2();
            String message = "Hello, ECDSA!";
            
            // 签名
            String signature = example.signMessage(message);
            System.out.println("Signature: " + signature);

            // 验签
            boolean isValid = example.verifySignature(message, signature);
            System.out.println("Is signature valid? " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}