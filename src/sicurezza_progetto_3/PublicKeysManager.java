/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.json.JSONException;
import org.json.JSONObject;

/**
 *
 * @author gennaroavitabile
 */
public class PublicKeysManager {
   
    private static PublicKeysManager  pkm = null;
    private JSONObject jPubDatabase;
    
    private PublicKeysManager(String fileChiaviPubbliche) throws IOException{
        this.jPubDatabase=KeychainUtils.getPubKeychain(fileChiaviPubbliche);
    }
    
    public static PublicKeysManager getPublicKeysManager() throws IOException{
        if(pkm == null){
           pkm = new PublicKeysManager("chiaviPub.txt"); 
        }
        return pkm;
    }
    
    public PublicKey getPublicKey(String user, String keyId){
        JSONObject j;
        try{
        j = new JSONObject(jPubDatabase.getString(user));
        }catch(JSONException ex){
            System.out.println("Errore Utente non presente!");
            return null;
        }
        byte[] decodedPubKey;
        try{
            decodedPubKey=Base64.getDecoder().decode(j.getString(keyId));
        }catch(JSONException ex){
            System.out.println("Errore chiave non presente!");
            return null;
        }
        String[] parameters=keyId.split("/");
        PublicKey publicKey = null;
        try{
            KeyFactory kf = KeyFactory.getInstance(parameters[1]);
            publicKey = kf.generatePublic(new X509EncodedKeySpec(decodedPubKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return publicKey;
        
    }

}
