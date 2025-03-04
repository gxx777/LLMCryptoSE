import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class DSASignatureExample3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public DSASignatureExample3() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String sign(String message) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(privateKey);
        dsa.update(message.getBytes(UTF_8));
        byte[] signature = dsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public boolean verify(String message, String signature) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(publicKey);
        dsa.update(message.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return dsa.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            DSASignatureExample3 dsaExample = new DSASignatureExample3();
            String message = "Hello, this is a test message for DSA signature.";

            // Sign the message
            String signature = dsaExample.sign(message);
            System.out.println("Signature: " + signature);

            // Verify the signature
            boolean isValid = dsaExample.verify(message, signature);
            System.out.println("Is the signature valid? " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}