import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // Generate DSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048); // Use secure key length
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Create a signature instance for DSA
        Signature sign = Signature.getInstance("SHA256withDSA");
        sign.initSign(privateKey);

        // Sign the message
        byte[] message = "Hello, world!".getBytes();
        sign.update(message);
        byte[] signature = sign.sign();
        System.out.println("Digital signature:");
        System.out.println(new String(signature));

        // Verify the signature
        Signature verifySign = Signature.getInstance("SHA256withDSA");
        verifySign.initVerify(publicKey);
        verifySign.update(message);
        boolean isVerified = verifySign.verify(signature);
        System.out.println("Signature verified: " + isVerified);
    }
}