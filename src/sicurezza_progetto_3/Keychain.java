/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.IOException;
import java.security.PrivateKey;
import org.json.JSONObject;

/**
 *
 * @author gennaroavitabile
 */
public class Keychain {
    
    JSONObject jKeyChain;


    public Keychain(String keychainFile, char[] password) throws IOException {   
        jKeyChain=KeychainUtils.decryptKeychain(password, keychainFile);
        jKeyChain=KeychainUtils.createEmptyKeychain(password, keychainFile);  
    }    
  
 
    public PrivateKey getPrivateKey(String identifier){
        
    }
    
    public String getPassword(String identifier){
        
    }
    

    
    
    
    
    
}
