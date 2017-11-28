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
import javax.crypto.ShortBufferException;

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
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, UnsupportedEncodingException, SignatureException, IllegalBlockSizeException, NotVerifiedSignException, ShortBufferException{
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
        
        
        
        //Genera richieste
        
        /*
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento1.txt");
        tsm.generateRequest("Caparezza.kc", "Caparezza", "prigioniero709".toCharArray(), "documenti/documento2.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento3.txt");
        tsm.generateRequest("Michele.kc", "Michele", "alterego".toCharArray(), "documenti/documento4.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento5.txt");
        tsm.generateRequest("Caparezza.kc", "Caparezza","prigioniero709".toCharArray(), "documenti/documento6.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/foto1.jpg");
        tsm.generateRequest("Michele.kc", "Michele", "alterego".toCharArray(), "documenti/lifestyle.mp3");
        
        tsm.generateRequest("Caparezza.kc", "Caparezza","prigioniero709".toCharArray(), "documenti/documento7.txt");
        tsm.generateRequest("Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/foto2.jpg");
        tsm.generateRequest("Michele.kc", "Michele", "alterego".toCharArray(), "documenti/documento8.txt");
        tsm.processRequests();
        */
        //Decifra marche
        /*
        tsm.decryptTimestamp("Mikimix.kc", "documenti/documento1.txt.marca.enc", "sanremo".toCharArray());
        tsm.decryptTimestamp("Mikimix.kc", "documenti/documento2.txt.marca.enc", "sanremo".toCharArray());
        tsm.decryptTimestamp("Mikimix.kc", "documenti/documento3.txt.marca.enc", "sanremo".toCharArray());
        tsm.decryptTimestamp("Mikimix.kc", "documenti/documento4.txt.marca.enc", "sanremo".toCharArray());
        tsm.decryptTimestamp("Mikimix.kc", "documenti/documento5.txt.marca.enc", "sanremo".toCharArray());
        tsm.decryptTimestamp("Mikimix.kc", "documenti/documento6.txt.marca.enc", "sanremo".toCharArray());
        tsm.decryptTimestamp("Mikimix.kc", "documenti/documento7.txt.marca.enc", "sanremo".toCharArray());
        tsm.decryptTimestamp("Mikimix.kc", "documenti/documento8.txt.marca.enc", "sanremo".toCharArray());*/
        //Verifica online
        System.out.println("----Primo Timestamp------");
        System.out.println("Verifica Offline true expected");
        System.out.println(tsm.verifyOffline("documenti/foto1.jpg", "documenti/foto1.jpg.marca.enc"));
        System.out.println("Verifica Offline false expected (Marca di un docuymento diverso)");
        System.out.println(tsm.verifyOffline("documenti/documento1.txt", "documenti/documento2.txt.marca.enc"));
        System.out.println("Verifica Online true expected");
        System.out.println(tsm.verifyOnline("documenti/foto1.jpg", "documenti/foto1.jpg.marca.enc","hashValues"));
        System.out.println("Verifica Online false expected (Marca di un docuymento diverso)");
        System.out.println(tsm.verifyOnline("documenti/documento1.txt", "documenti/documento2.txt.marca.enc","hashValues"));
        System.out.println("Verifica Catena true expected");
        System.out.println(tsm.verifyChain("documenti/foto1.jpg", "documenti/foto1.jpg.marca.enc","hashValues"));
        System.out.println("Verifica Catena false expected (Hash Value Truccato)");
        System.out.println(tsm.verifyChain("documenti/foto1.jpg", "documenti/foto1.jpg.marca.enc","hashValuesContraffazione"));


        System.out.println("----Secondo Timestamp minore di 8------");
        System.out.println("Verifica Offline true expected");
        System.out.println(tsm.verifyOffline("documenti/foto2.jpg", "documenti/foto2.jpg.marca.enc"));
        System.out.println("Verifica Offline false expected (Marca di un docuymento diverso)");
        System.out.println(tsm.verifyOffline("documenti/documento7.txt", "documenti/documento8.txt.marca.enc"));
        System.out.println("Verifica Online true expected");
        System.out.println(tsm.verifyOnline("documenti/foto2.jpg", "documenti/foto2.jpg.marca.enc","hashValues"));
        System.out.println("Verifica Online false expected (Marca di un docuymento diverso)");
        System.out.println(tsm.verifyOnline("documenti/documento7.txt", "documenti/documento8.txt.marca.enc","hashValues"));

    }

    
}
