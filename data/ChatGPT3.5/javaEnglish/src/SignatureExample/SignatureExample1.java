import java.security.*;

public class SignatureExample1 {
    
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Get private and public keys
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Create a message to be signed
        String message = "This is a secure message to be signed";
        
        // Sign the message
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();
        
        // Verify the message
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean verified = signature.verify(signedMessage);
        
        if (verified) {
            System.out.println("Message verified successfully");
        } else {
            System.out.println("Message verification failed");
        }
    }
}