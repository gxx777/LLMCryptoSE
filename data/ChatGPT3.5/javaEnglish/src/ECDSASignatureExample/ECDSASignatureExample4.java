import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class ECDSASignatureExample4 {

    public static void main(String[] args) throws Exception {
    	
        // Generate ECDSA keypair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.genKeyPair();
        
        // Generate message to be signed
        String message = "Hello, World!";
        
        // Create signature
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        
        // Print signature
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signatureBytes));
        
        // Verify signature
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message.getBytes());
        boolean verified = verifier.verify(signatureBytes);

        if (verified) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature verification failed");
        }
    }
}