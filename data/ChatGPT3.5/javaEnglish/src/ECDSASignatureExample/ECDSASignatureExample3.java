import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class ECDSASignatureExample3 {
    
    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes());
        byte[] signature = ecdsa.sign();
        return signature;
    }

    public static boolean verifySignature(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(publicKey);
        ecdsa.update(message.getBytes());
        return ecdsa.verify(signature);
    }

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        String message = "Hello, world!";
        
        byte[] signature = signMessage(message, keyPair.getPrivate());
        System.out.println("Signature: " + new String(signature));
        
        boolean verified = verifySignature(message, signature, keyPair.getPublic());
        System.out.println("Signature verified: " + verified);
    }
}