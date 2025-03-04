import java.security.*;

public class SignatureExample1 {

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Get private and public keys
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Create signature object
            Signature signature = Signature.getInstance("SHA256withRSA");

            // Signing the data
            String data = "This is a message to be signed";
            byte[] dataBytes = data.getBytes();
            signature.initSign(privateKey);
            signature.update(dataBytes);
            byte[] digitalSignature = signature.sign();

            System.out.println("Digital Signature: " + new String(digitalSignature));

            // Verifying the data
            signature.initVerify(publicKey);
            signature.update(dataBytes);
            boolean verified = signature.verify(digitalSignature);

            if (verified) {
                System.out.println("Signature verified: Data is intact");
            } else {
                System.out.println("Signature verification failed: Data has been tampered with");
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }
}