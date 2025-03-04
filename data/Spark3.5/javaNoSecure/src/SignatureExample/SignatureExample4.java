import java.security.*;

public class SignatureExample4 {
    private static final String SIGNING_ALGORITHM = "SHA256withRSA";

    public static byte[] sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance(SIGNING_ALGORITHM);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));
        return privateSignature.sign();
    }

    public static boolean verify(String plainText, byte[] signatureToVerify, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance(SIGNING_ALGORITHM);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));
        return publicSignature.verify(signatureToVerify);
    }

    public static void main(String[] args) throws Exception {
        // Generate key pair for demonstration. In practice you would have a secure way of distributing and storing keys.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String message = "This is a test message";
        byte[] signature = sign(message, privateKey);

        System.out.println("Signature: " + new String(signature, "UTF-8"));
        System.out.println("Verification: " + verify(message, signature, publicKey));
    }
}