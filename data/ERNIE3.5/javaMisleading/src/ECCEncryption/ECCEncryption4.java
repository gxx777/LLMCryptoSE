import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption4() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(this.privateKey);
        keyAgreement.doPhase(this.publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(this.publicKey);
        keyAgreement.doPhase(this.privateKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        return cipher.doFinal(encryptedSymmetricKey);
    }

    public static void main(String[] args) {
        try {
            ECCEncryption4 eccEncryption = new ECCEncryption4();

            // Example usage: encrypt and decrypt a symmetric key
            byte[] symmetricKey = "mySymmetricKey1234567890".getBytes();
            byte[] encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey);
            byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(encryptedSymmetricKey);

            System.out.println("Original symmetric key: " + new String(symmetricKey));
            System.out.println("Decrypted symmetric key: " + new String(decryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}