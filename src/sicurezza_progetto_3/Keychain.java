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
    String keychainFile;

    public Keychain(String keychainFile, char[] password, boolean isold) throws IOException {   
        this.keychainFile=keychainFile;
        if(isold){
            jKeyChain=KeychainUtils.decryptKeychain(password, keychainFile);
        }
        else{
            jKeyChain=KeychainUtils.createEmptyKeychain(password, keychainFile);
        } 
    }    
  
 
    public PrivateKey getPrivateKey(String identifier){
        
    }
    
    public String getPassword(String identifier){
        
    }
    
    public void addPrivateKey(String identifier, PrivateKey pk){
        
    }
    
    public void addPassword(String identifier, String password){
        
    }
    
    public void store(){
        
    }
    
    
    
    
    
    
}
