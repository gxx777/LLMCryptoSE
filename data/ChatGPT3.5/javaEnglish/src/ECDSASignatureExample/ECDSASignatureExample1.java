import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.Signature;

public class ECDSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        
        // Generating key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // Creating signature instance for signing
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        
        // Signing the message
        String message = "This is a test message";
        ecdsaSign.initSign(keyPair.getPrivate());
        ecdsaSign.update(message.getBytes());
        byte[] signature = ecdsaSign.sign();
        
        System.out.println("Original message: " + message);
        System.out.println("Signature: " + bytesToHex(signature));
        
        // Verifying the signature
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(keyPair.getPublic());
        ecdsaVerify.update(message.getBytes());
        boolean isVerified = ecdsaVerify.verify(signature);
        
        System.out.println("Signature verified: " + isVerified);
    }
    
    // Helper method to convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}