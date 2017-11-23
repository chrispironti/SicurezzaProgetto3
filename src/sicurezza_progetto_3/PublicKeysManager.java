/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

/**
 *
 * @author gennaroavitabile
 */
public class PublicKeysManager {
   
    private static PublicKeysManager  pkm = null;
    private String fileChiaviPubbliche;
    
    private PublicKeysManager(String fileChiaviPubbliche) {
        this.fileChiaviPubbliche=fileChiaviPubbliche;
    }
    
    public static synchronized PublicKeysManager getPublicKeysManager(){
        if(pkm == null){
           pkm = new PublicKeysManager("Nomedelfile"); 
        }
        return pkm;
    }
    
}
