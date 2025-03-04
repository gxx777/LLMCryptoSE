import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class DSASignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public DSASignatureExample4() throws NoSuchAlgorithmException {
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
        byte[] realSig = dsa.sign();
        return Base64.getEncoder().encodeToString(realSig);
    }

    public boolean verify(String message, String signature) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(publicKey);
        dsa.update(message.getBytes(UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return dsa.verify(sigBytes);
    }

    public static void main(String[] args) throws Exception {
        DSASignatureExample4 dsaExample = new DSASignatureExample4();
        String message = "Hello, DSA!";
        String signature = dsaExample.sign(message);
        System.out.println("Signature: " + signature);
        boolean isVerified = dsaExample.verify(message, signature);
        System.out.println("Verification result: " + isVerified);
    }
}