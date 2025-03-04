import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class ECDSASignatureExample4 {

    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Sign the message
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(message.getBytes());
        byte[] signature = ecdsaSign.sign();
        
        // Verify the signature
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(message.getBytes());
        boolean isVerified = ecdsaVerify.verify(signature);
        
        if (isVerified) {
            System.out.println("Signature verified successfully.");
        } else {
            System.out.println("Signature verification failed.");
        }
    }
}