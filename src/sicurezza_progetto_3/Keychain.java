/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.IOException;
import org.json.JSONObject;

/**
 *
 * @author gennaroavitabile
 */
public class Keychain {
    
    JSONObject jKeyChain;

    public Keychain(String KeychainFile, char[] password, boolean isold) throws IOException {   
        if(isold){
            jKeyChain=KeychainUtils.decryptKeychain(password, KeychainFile);
        }
        else{
            jKeyChain=KeychainUtils.createEmptyKeycahin(password, KeychainFile);
        } 
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
