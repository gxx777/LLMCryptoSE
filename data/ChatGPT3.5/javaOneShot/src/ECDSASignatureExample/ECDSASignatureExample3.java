import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import java.util.Base64;

public class ECDSASignatureExample3 {

    private static final String ALGORITHM = "SHA256withECDSA";
    private static final String CURVE_NAME = "secp256k1";

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(CURVE_NAME);
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Get private key and public key
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

            // Display private key and public key
            System.out.println("Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            System.out.println("Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            // Create signature
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(privateKey);

            String message = "Hello, ECDSA!";
            signature.update(message.getBytes());
            byte[] signatureBytes = signature.sign();

            System.out.println("Signature: " + Base64.getEncoder().encodeToString(signatureBytes));

            // Verify signature
            signature.initVerify(publicKey);
            signature.update(message.getBytes());
            boolean verified = signature.verify(signatureBytes);

            if (verified) {
                System.out.println("Signature verified!");
            } else {
                System.out.println("Signature verification failed!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}