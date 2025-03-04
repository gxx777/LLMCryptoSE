import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Base64;

public class ECDSASignatureExample4 {

    private static final String ALGORITHM = "SHA256withECDSA";

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, ECDSA!";

        // Sign the message
        byte[] signature = sign(message, privateKey);

        // Verify the signature
        boolean verified = verify(message, signature, publicKey);
        System.out.println("Signature verified: " + verified);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] sign(String message, PrivateKey privateKey) throws Exception {
        Signature ecdsa = Signature.getInstance(ALGORITHM);
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes());
        return ecdsa.sign();
    }

    public static boolean verify(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature ecdsa = Signature.getInstance(ALGORITHM);
        ecdsa.initVerify(publicKey);
        ecdsa.update(message.getBytes());
        return ecdsa.verify(signature);
    }
}