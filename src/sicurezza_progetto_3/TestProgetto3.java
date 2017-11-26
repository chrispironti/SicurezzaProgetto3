package sicurezza_progetto_3;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Christopher
 */
public class TestProgetto3 {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, UnsupportedEncodingException, SignatureException, IllegalBlockSizeException, NotVerifiedSignException{
       /* Map<String, char[]> users = new HashMap<>();
        Map<String,String> filesChiaviPrivate = new HashMap<>();
        users.put("Caparezza", "prigioniero709".toCharArray());
        filesChiaviPrivate.put("Caparezza", "Caparezza.kc");
        users.put("Michele","alterego".toCharArray());
        filesChiaviPrivate.put("Michele", "Michele.kc");
        users.put("Mikimix","sanremo".toCharArray());
        filesChiaviPrivate.put("Mikimix", "Mikimix.kc");
        users.put("TSA","TSAPass".toCharArray());
        filesChiaviPrivate.put("TSA", "TSA.kc");
        KeychainUtils.generateKeyPairs(users, "chiaviPub.txt", filesChiaviPrivate);*/
        
        TSA TSAserver = new TSA();
        TimestampManager tsm = new TimestampManager(TSAserver);
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento1.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento2.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento3.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento4.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento5.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento6.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento7.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento8.txt");
    }

    
}
