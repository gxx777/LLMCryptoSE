import java.security.*;
import java.util.Base64;

public class ECDSASignatureExample4 {
    private static final String SIGNING_ALGORITHM = "SHA256withECDSA";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(256, random);
        return keyGen.generateKeyPair();
    }

    public static byte[] sign(String plainText, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature privateSignature = Signature.getInstance(SIGNING_ALGORITHM);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes());
        return privateSignature.sign();
    }

    public static boolean verify(String plainText, byte[] signatureToVerify, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance(SIGNING_ALGORITHM);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes());
        return publicSignature.verify(signatureToVerify);
    }

    public static void main(String[] args) {
        try {
            KeyPair keyPair = generateKeyPair();
            String message = "This is a test message";
            byte[] signature = sign(message, keyPair.getPrivate());
            System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));
            boolean isVerified = verify(message, signature, keyPair.getPublic());
            System.out.println("Signature verified: " + isVerified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}