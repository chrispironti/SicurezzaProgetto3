/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author gennaroavitabile
 */
public class KeychainTester {
    
        public static void main(String[] args) throws IOException {
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
        PrivateKey mypk= k.getPrivateKey("Key/RSA/1024/Main");
        System.out.println(mypk.toString());
        
        
        
        
        
    }
    
}
