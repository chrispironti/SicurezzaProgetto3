/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.json.JSONArray;
import org.json.JSONObject;


public class DTSUtils {
    
    public static byte[] arrayConcat(byte[] array1, byte[] array2){
        
       byte[] array1and2 = new byte[array1.length + array2.length];
       System.arraycopy(array1, 0, array1and2, 0, array1.length);
       System.arraycopy(array2, 0, array1and2, array1.length, array2.length);
       return array1and2;
   }
    
    public static void verifyText(byte[] plaintext, byte[] firmaDSA, PublicKey DSAKeyPub) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NotVerifiedSignException{

    Signature dsa = Signature.getInstance("SHA256withDSA");
    dsa.initVerify(DSAKeyPub);
    dsa.update(plaintext);
    if(!dsa.verify(firmaDSA))
        throw new NotVerifiedSignException();
    }
    
    public static JSONObject readStamp(String marcaFile) throws IOException{
        
        byte[] encoded = Files.readAllBytes(Paths.get(marcaFile));
        return new JSONObject(new String(encoded, "UTF8"));
    }
    
    public static JSONArray readHashValues(String hashFile) throws IOException{
        
         return new JSONArray(new String(Files.readAllBytes(Paths.get(hashFile)),"UTF-8"));
    }
}
