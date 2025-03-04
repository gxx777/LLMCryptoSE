import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SignatureExample4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public String sign(String message) throws Exception {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(this.privateKey);
        rsa.update(message.getBytes(UTF_8));
        byte[] signature = rsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public boolean verify(String message, String signature) throws Exception {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(this.publicKey);
        rsa.update(message.getBytes(UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return rsa.verify(sigBytes);
    }

    public static void main(String[] args) throws Exception {
        SignatureExample4 signer = new SignatureExample4();

        String message = "Hello, World!";
        String signature = signer.sign(message);
        System.out.println("Signature: " + signature);

        boolean isValid = signer.verify(message, signature);
        System.out.println("Is signature valid? " + isValid);
    }
}