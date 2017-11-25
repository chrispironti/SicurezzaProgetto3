/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SealedObject;
import org.json.JSONObject;
import static sicurezza_progetto_3.KeychainUtils.IV_SIZE;
import static sicurezza_progetto_3.KeychainUtils.SALT_SIZE;

/**
 *
 * @author gennaroavitabile
 */
public class KeychainTester {
    
        public static final int IV_SIZE=16;
    public static final int SALT_SIZE=16;
    
        public static void main(String[] args) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException {
        // TODO code application logic here
        
        /*
        Map<String, char[]> passwords= new HashMap<>();
        Map<String, String> filesChiaviPrivate= new HashMap<>();
        passwords.put("Caparezza", "prigioniero709".toCharArray());
        filesChiaviPrivate.put("Caparezza", "Caparezza.kc");
        passwords.put("Michele","alterego".toCharArray());
        filesChiaviPrivate.put("Michele", "Michele.kc");
        KeychainUtils.generateKeyPairs(passwords, "Pubdatabase", filesChiaviPrivate);
        */
        /*
        Keychain k= new Keychain("Caparezza.kc", "prigioniero709".toCharArray());
        PrivateKey mypk= k.getPrivateKey("Key/RSA/1024/Main");
        System.out.println(mypk.toString());
        */
        
        JSONObject j= new JSONObject();
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = null;
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024,random);
        KeyPair RSAKeys1024 = keyPairGenerator.generateKeyPair();
        j.put("Key/RSA/1024/Main", Base64.getEncoder().encodeToString(RSAKeys1024.getPublic().getEncoded()));
        j.put("Key/RSA/1024/Main2", Base64.getEncoder().encodeToString(RSAKeys1024.getPrivate().getEncoded()));
        byte salt[] = new byte[SALT_SIZE];
	random.nextBytes(salt);
        byte iv[]= new byte[IV_SIZE];
        random.nextBytes(iv);
        Cipher c =KeychainUtils.cipherFromPass(salt, iv, "gavit".toCharArray());
        SealedObject so = new SealedObject(j.toString(), c);
        String s= (String) so.getObject(c);
        JSONObject newj= new JSONObject(s);
        System.out.println(newj.toString());
        
        
        
    }
    
}
