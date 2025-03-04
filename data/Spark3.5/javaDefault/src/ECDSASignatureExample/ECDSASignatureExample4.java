import java.security.*;
import java.util.Arrays;

public class ECDSASignatureExample4 {
    private static final String SIGNING_ALGORITHM = "SHA256withECDSA";

    public static byte[] sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance(SIGNING_ALGORITHM);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));
        byte[] signature = privateSignature.sign();
        return signature;
    }

    public static boolean verify(String plainText, byte[] signatureToVerify, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance(SIGNING_ALGORITHM);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));
        return publicSignature.verify(signatureToVerify);
    }

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String plainText = "Hello, World!";
        byte[] signature = sign(plainText, privateKey);
        System.out.println("Signature: " + Arrays.toString(signature));

        boolean isCorrect = verify(plainText, signature, publicKey);
        System.out.println("Signature correct: " + isCorrect);
    }
}