import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStore.PasswordProtection;

public class PasswordProtection1 {

    private KeyStore keyStore;

    public PasswordProtection1() {
        try {
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void storePassword(String alias, char[] password) {
        try {
            keyStore.setEntry(alias, (KeyStore.Entry) new PasswordProtection(password), null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public char[] retrievePassword(String alias) {
        try {
            PasswordProtection protection = (PasswordProtection) keyStore.getEntry(alias, null);
            return protection.getPassword();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        PasswordProtection1 passwordProtection = new PasswordProtection1();
        passwordProtection.storePassword("testAlias", "testPassword".toCharArray());
        char[] retrievedPassword = passwordProtection.retrievePassword("testAlias");
        System.out.println("Retrieved password: " + new String(retrievedPassword));
    }
}