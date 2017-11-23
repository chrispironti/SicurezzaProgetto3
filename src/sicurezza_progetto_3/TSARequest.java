/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.*;
import org.json.JSONObject;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;

/**

 */
public class TSARequest {
    public byte[] info;
    public byte[] sign;
    public String signType;
    
    /*Riceve l'oggetto user e l'oggetto JSON contente id utente e hash message. 
    Lo converte in byte, lo firma 
    usando la propria chiave DSA privata, lo cifra con la chiave RSA pubblica 
    del server TSA, e lo converte in stringa mettendolo nel campo info    
    */
    public TSARequest(User user, byte[] msgDigest, String signType) throws IOException, BadPaddingException{ //signType lo devo passare da qui?
        this.signType = signType;
        
        //Costruisco il Json e ottengo i byte
        byte[] jReqBytes = createJson(user, msgDigest);
        
        //Firma dei byte del Json con la chiave privata dell'user
        PrivateKey DSAPrKey = user.getDsaPrivKey();
        signText(jReqBytes, DSAPrKey);
        
        //Cifratura con la chiave pubblica della TSA
        //PublicKey RSAPubKey = TSAServer.getPublicKey?
        //this.encryptText(jReqBytes, RSAPubKey);
    }
    
    private byte[] createJson(User user, byte[] msgDigest){
        JSONObject jRequest = new JSONObject();
        jRequest.put("userID", user.getID());
        jRequest.put("msgDigest", msgDigest);
        
        //Ottengo i byte dal Json
        byte[] jReqBytes = null;
        try {
            jReqBytes = jRequest.toString().getBytes("UTF8");
        } catch (UnsupportedEncodingException ex) {
            System.out.println("Encoding non supportato");
        }
        
        return jReqBytes;
    }
    
    private void signText(byte[] plaintext, PrivateKey DSAPrKey){
        Signature dsa = null;
        try {    
            dsa = Signature.getInstance(signType);
            dsa.initSign(DSAPrKey);
            dsa.update(plaintext);
            sign = dsa.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private void encryptText(byte[] plainText, PublicKey RSAPubKey){
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.ENCRYPT_MODE, RSAPubKey);
            info = cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                System.exit(1);
        }
    }
}
