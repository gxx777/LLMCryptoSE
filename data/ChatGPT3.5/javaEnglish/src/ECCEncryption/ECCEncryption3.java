import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

public class ECCEncryption3 {

    private static final String ECC_ALGORITHM = "EC";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "ECIES";

    public SecretKey generateSymmetricKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGenerator.init(256); // Using AES with 256 bits key size
        return keyGenerator.generateKey();
    }

    public byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    public SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKeyBytes, SYMMETRIC_ALGORITHM);
    }

    public KeyPair generateKeyPair() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(ECC_ALGORITHM, "BC");
        keyGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {
        ECCEncryption3 eccEncryption = new ECCEncryption3();

        KeyPair keyPair = eccEncryption.generateKeyPair();
        SecretKey symmetricKey = eccEncryption.generateSymmetricKey();

        byte[] encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey, keyPair.getPublic());
        SecretKey decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(encryptedSymmetricKey, keyPair.getPrivate());

        System.out.println("Original symmetric key: " + Base64.getEncoder().encodeToString(symmetricKey.getEncoded()));
        System.out.println("Decrypted symmetric key: " + Base64.getEncoder().encodeToString(decryptedSymmetricKey.getEncoded()));
    }
}