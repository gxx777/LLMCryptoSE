import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class ECCEncryption3 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Generate ECC keys
        KeyPair eccKeyPair = generateECCKeyPair();
        PublicKey publicKey = eccKeyPair.getPublic();
        PrivateKey privateKey = eccKeyPair.getPrivate();

        // Generate a symmetric key
        SecretKey symmetricKey = generateSymmetricKey();

        // Encrypt the symmetric key using ECC public key
        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey.getEncoded(), publicKey);

        // Decrypt the symmetric key using ECC private key
        byte[] decryptedSymmetricKey = decryptSymmetricKey(encryptedSymmetricKey, privateKey);

        // Compare the original and decrypted symmetric keys
        if (Arrays.equals(symmetricKey.getEncoded(), decryptedSymmetricKey)) {
            System.out.println("Symmetric key decryption successful!");
        } else {
            System.out.println("Symmetric key decryption failed!");
        }
    }

    private static KeyPair generateECCKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private static byte[] encryptSymmetricKey(byte[] symmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    private static byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }
}