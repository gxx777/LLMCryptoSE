import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Base64;

public class DSASignatureExample3 {

    public static void main(String[] args) throws Exception {
        
        // Generate DSA public/private key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        // Create public key
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);

        // Create private key
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // Sign a message
        String message = "Hello, this is a secret message!";
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();

        System.out.println("Signed message: " + Base64.getEncoder().encodeToString(signedMessage));

        // Verify the message
        Signature verifier = Signature.getInstance("SHA1withDSA");
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes());
        boolean isValid = verifier.verify(signedMessage);

        if (isValid) {
            System.out.println("Message is verified successfully!");
        } else {
            System.out.println("Message verification failed!");
        }
    }
}