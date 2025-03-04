import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryption4 {
    
    private static final String ALGORITHM = "AES";
    private static final String ECC_ALGORITHM = "EC";
    private static final String CURVE_NAME = "secp256r1";
    
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public ECCEncryption4() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        // Generate ECC Key Pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ECC_ALGORITHM, "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(CURVE_NAME);
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        keyPairGenerator.initialize(ecGenParameterSpec, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    public byte[] encrypt(byte[] input) throws Exception {
        // Generate AES Symmetric Key
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        
        // Encrypt Symmetric Key with ECC Public Key
        Cipher cipher = Cipher.getInstance(ECC_ALGORITHM, "BC");
        cipher.init(Cipher.WRAP_MODE, publicKey);
        byte[] wrappedKey = cipher.wrap(new SecretKeySpec(secretKey.getEncoded(), ALGORITHM));
        
        // Encrypt Data with Symmetric Key
        Cipher dataCipher = Cipher.getInstance(ALGORITHM);
        dataCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return dataCipher.doFinal(input);
    }

    public byte[] decrypt(byte[] input) throws Exception {
        // Decrypt Symmetric Key with ECC Private Key
        Cipher cipher = Cipher.getInstance(ECC_ALGORITHM, "BC");
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        SecretKey secretKey = (SecretKey) cipher.unwrap(input, ALGORITHM, Cipher.SECRET_KEY);
        
        // Decrypt Data with Symmetric Key
        Cipher dataCipher = Cipher.getInstance(ALGORITHM);
        dataCipher.init(Cipher.DECRYPT_MODE, secretKey);
        return dataCipher.doFinal(input);
    }

    public static void main(String[] args) throws Exception {
        ECCEncryption4 ecc = new ECCEncryption4();
        
        String plainText = "Hello, World!";
        byte[] encryptedData = ecc.encrypt(plainText.getBytes());
        byte[] decryptedData = ecc.decrypt(encryptedData);
        
        System.out.println("Original: " + plainText);
        System.out.println("Encrypted: " + new String(encryptedData));
        System.out.println("Decrypted: " + new String(decryptedData));
    }
}