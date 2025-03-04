import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.getPrivateKey;
import static org.bouncycastle.jce.provider.BouncyCastleProvider.getPublicKey;

public class AsymmetricEncryption4 {

    private static final String ALGORITHM = "RSA";

    public static void generateKeyPair(String publicKeyFile, String privateKeyFile) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(2048);
        
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        try (FileOutputStream publicFileStream = new FileOutputStream(publicKeyFile)) {
            publicFileStream.write(publicKey.getEncoded());
        }
        
        try (FileOutputStream privateFileStream = new FileOutputStream(privateKeyFile)) {
            privateFileStream.write(privateKey.getEncoded());
        }
    }

    public static byte[] encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        return new String(cipher.doFinal(data));
    }

    public static void main(String[] args) throws Exception {
        String publicKeyFile = "public.key";
        String privateKeyFile = "private.key";
        
        generateKeyPair(publicKeyFile, privateKeyFile);

        PublicKey publicKey = getPublicKey(SubjectPublicKeyInfo.getInstance(publicKeyFile));
        PrivateKey privateKey = getPrivateKey(PrivateKeyInfo.getInstance(privateKeyFile));
        
        String data = "Sensitive data to be encrypted";
        byte[] encryptedData = encrypt(data, publicKey);
        String decryptedData = decrypt(encryptedData, privateKey);
        
        System.out.println("Original data: " + data);
        System.out.println("Encrypted data: " + new String(encryptedData));
        System.out.println("Decrypted data: " + decryptedData);
    }
}