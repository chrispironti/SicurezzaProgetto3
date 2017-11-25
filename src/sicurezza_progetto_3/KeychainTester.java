/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;
import static sicurezza_progetto_3.KeychainUtils.IV_SIZE;
import static sicurezza_progetto_3.KeychainUtils.SALT_SIZE;

/**
 *
 * @author gennaroavitabile
 */
public class KeychainTester {

    
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
        
        
        Keychain k= new Keychain("Caparezza.kc", "prigioniero709".toCharArray());
        /*PrivateKey mypk= k.getPrivateKey("Key/RSA/1024/Main");
        System.out.println(Base64.getEncoder().encodeToString(mypk.getEncoded()));
        System.out.println(k.getPassword("Pass/Facebook/Tedua"));
        System.out.println(k.getPassword("Pass/Facebook/Detua"));
        System.out.println(k.getPassword("Pass/Gmail/Gavitmc"));
        List<String> passtormv= new LinkedList<>();
        passtormv.add("Pass/Facebook/Tedua");
        KeychainUtils.rmvInKeychain("Caparezza.kc", passtormv, "prigioniero709".toCharArray());*/
        System.out.println(k.getPassword("Pass/Facebook/Detua"));
        System.out.println(k.getPassword("Pass/Gmail/Gavitmc"));
        //System.out.println(k.getPassword("Pass/Facebook/Tedua"));
        
        PublicKeysManager mypkm= PublicKeysManager.getPublicKeysManager();
        PublicKey lolo= mypkm.getPublicKey("Michele", "Key/RSA/1024/Main");
        System.out.println(Base64.getEncoder().encodeToString(lolo.getEncoded()));
        
        
   /*
        Map<String, String> passtoadd= new HashMap<>();
        passtoadd.put("Pass/Facebook/Tedua", "wasabi");
        passtoadd.put("Pass/Facebook/Detua", "wasabone");
        passtoadd.put("Pass/Gmail/Gavitmc", "polloalforno");
        KeychainUtils.addPassInKeychain("Caparezza.kc", passtoadd, "prigioniero709".toCharArray());
        */
        
        
        /*
        SERJSONObject j= new SERJSONObject();
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
        System.out.println(j.toString());
        Cipher c = KeychainUtils.cipherEncFromPass(salt, iv, "gavit".toCharArray());
        Cipher cipher= KeychainUtils.cipherDecFromPass(salt, iv, "gavit".toCharArray());
        SealedObject so = new SealedObject(j.toString(), c);
        String s = (String) so.getObject(cipher);
        System.out.println(s);
*/
        
        
        
    }
    
}
