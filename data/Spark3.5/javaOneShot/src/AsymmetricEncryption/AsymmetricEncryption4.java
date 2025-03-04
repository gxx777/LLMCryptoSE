import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncryption4 {

    private static final String RSA = "RSA";
    private static final String AES = "AES";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
}