import java.security.*;
import java.util.Arrays;

public class DSASignatureExample2 {
    public static void main(String[] args) throws Exception {
        // Create a Signature object and initialize it with the private key
        Signature dsa = Signature.getInstance("SHA1withDSA");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();
        dsa.initSign(pair.getPrivate());

        String msg = "Hello, World!";
        byte[] strByte = msg.getBytes("UTF8");
        dsa.update(strByte);

        // Now that all the data to be signed has been seen, generate a signature for it
        byte[] realSig = dsa.sign();

        // Reset the Signature object for verification and initialize it with the public key
        dsa.initVerify(pair.getPublic());

        // Feed the data we want to verify
        dsa.update(strByte);

        // Verify the signature
        boolean verifies = dsa.verify(realSig);

        System.out.println("signature verifies: " + verifies);
    }
}