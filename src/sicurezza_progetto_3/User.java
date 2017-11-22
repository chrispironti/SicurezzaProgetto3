/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.io.IOException;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import org.json.*;

/**
 * Potrebbe servirci. Ancora, possiamo usare JSON volendo.
 * 
 */
public class User {
    private String ID;
    private JSONObject keyRingPriv;
    private JSONObject keyRingPub;

    public User(String ID, char[] password, String KeychainFilePriv, String keychainFilePub) throws IOException {
        this.ID = ID;
        this.keyRingPriv = KeychainUtils.decryptKeychain(password, KeychainFilePriv);
        this.keyRingPub = KeychainUtils.getPubKeychain(keychainFilePub);
    }


    public PublicKey getRsaPubKey() throws IOException{
        
        byte[] decodedPubKey=Base64.getDecoder().decode(this.keyRingPub.getString("ChiaveRSA2048Pub"));
        PublicKey publicKey = null;
        try{
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(new X509EncodedKeySpec(decodedPubKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return publicKey;
    }
    
    public PublicKey getDsaPubKey() throws IOException{

        byte[] decodedPubKey=Base64.getDecoder().decode(this.keyRingPub.getString("ChiaveDSA2048Pub"));
        PublicKey publicKey = null;
        try{
            KeyFactory kf = KeyFactory.getInstance("DSA");
            publicKey = kf.generatePublic(new X509EncodedKeySpec(decodedPubKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return publicKey;
    }
    
    
    public PrivateKey getDsaPrivKey() throws IOException, BadPaddingException{
        
        byte[] decodedPrivKey=Base64.getDecoder().decode(this.keyRingPriv.getString("ChiaveDSA2048Priv"));
        PrivateKey privateKey = null;
        try{
            KeyFactory kf = KeyFactory.getInstance("DSA");
            privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decodedPrivKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return privateKey; 
    }
    
    
    public PrivateKey getRsaPrivKey() throws IOException, BadPaddingException{
        
        byte[] decodedPrivKey=Base64.getDecoder().decode(this.keyRingPriv.getString("ChiaveRSA2048Priv"));
        PrivateKey privateKey = null;
        try{
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decodedPrivKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return privateKey;        
    }    

    public String getID() {
        return ID;
    }
    
}
