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
public class PublicKeysManager {
   
    private static PublicKeysManager  pkm = null;
    private JSONObject jPubDatabase;
    
    private PublicKeysManager(String fileChiaviPubbliche) throws IOException{
        this.jPubDatabase=KeychainUtils.getPubKeychain(fileChiaviPubbliche);
    }
    
    public static synchronized PublicKeysManager getPublicKeysManager() throws IOException{
        if(pkm == null){
           pkm = new PublicKeysManager("Nomedelfile"); 
        }
        return pkm;
    }
    
}
