/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.json.JSONException;
import org.json.JSONObject;

/**
 *
 * @author gennaroavitabile
 */
public class Keychain {
    
    JSONObject jKeyChain;


    public Keychain(String keychainFile, char[] password) throws IOException {    
        jKeyChain=KeychainUtils.decryptKeychain(password, keychainFile);
    }    
  
 
    public PrivateKey getPrivateKey(String identifier){
        
        String[] parameters= identifier.split("/");
        PrivateKey k= null;
        String keytomodify;
        try{
            keytomodify=jKeyChain.getString(identifier);
        }catch(JSONException ex){
            System.out.println("Errore chiave non presente!");
            return null;
        }
        byte[] decodedPrivKey=Base64.getDecoder().decode(keytomodify);
        try{
            k=KeyFactory.getInstance(parameters[1]).generatePrivate(new PKCS8EncodedKeySpec(decodedPrivKey));
        }catch(InvalidKeySpecException| NoSuchAlgorithmException ex){
            ex.printStackTrace();
        }
        return k;
    }
    
    public String getPassword(String identifier){
        try{
            return jKeyChain.getString(identifier);
        }catch(JSONException ex){
            System.out.println("Errore password non presente");
            return null;
        }
    }
}
