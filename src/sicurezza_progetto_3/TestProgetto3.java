package sicurezza_progetto_3;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
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
        
        TSA TSAserver = new TSA("pubblici/hashValues");
        TimestampManager tsm = new TimestampManager(TSAserver);
        
        //Genera richieste
        
        tsm.generateRequest("keyring/Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento1.txt");
        tsm.generateRequest("keyring/Caparezza.kc", "Caparezza", "prigioniero709".toCharArray(), "documenti/documento2.txt");
        tsm.generateRequest("keyring/Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento3.txt");
        tsm.generateRequest("keyring/Michele.kc", "Michele", "alterego".toCharArray(), "documenti/documento4.txt");
        tsm.generateRequest("keyring/Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento5.txt");
        tsm.generateRequest("keyring/Caparezza.kc", "Caparezza","prigioniero709".toCharArray(), "documenti/documento6.txt");
        tsm.generateRequest("keyring/Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/foto1.jpg");
        tsm.generateRequest("keyring/Michele.kc", "Michele", "alterego".toCharArray(), "documenti/lifestyle.mp3");
        
        tsm.generateRequest("keyring/Caparezza.kc", "Caparezza","prigioniero709".toCharArray(), "documenti/documento7.txt");
        tsm.generateRequest("keyring/Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/foto2.jpg");
        tsm.generateRequest("keyring/Michele.kc", "Michele", "alterego".toCharArray(), "documenti/documento8.txt");
        tsm.processRequests();       
        //Verifiche
        System.out.println("----Primo Timestamp------");
        System.out.println("Verifica Offline true expected");
        System.out.println(tsm.verifyOffline("documenti/foto1.jpg", "marche/foto1.jpg.marca"));
        System.out.println("Verifica Offline false expected (Marca di un docuymento diverso)");
        System.out.println(tsm.verifyOffline("documenti/documento1.txt", "marche/documento2.txt.marca"));
        System.out.println("Verifica Online true expected");
        System.out.println(tsm.verifyOnline("documenti/foto1.jpg", "marche/foto1.jpg.marca","pubblici/hashValues",0));
        System.out.println("Verifica Online false expected (Marca di un docuymento diverso)");
        System.out.println(tsm.verifyOnline("documenti/documento1.txt", "marche/documento2.txt.marca","pubblici/hashValues",0));
        System.out.println("----Secondo Timestamp minore di 8------");
        System.out.println("Verifica Offline true expected");
        System.out.println(tsm.verifyOffline("documenti/foto2.jpg", "marche/foto2.jpg.marca"));
        System.out.println("Verifica Offline false expected (Marca di un docuymento diverso)");
        System.out.println(tsm.verifyOffline("documenti/documento7.txt", "marche/documento8.txt.marca"));
        System.out.println("Verifica Online true expected");
        System.out.println(tsm.verifyOnline("documenti/foto2.jpg", "marche/foto2.jpg.marca","pubblici/hashValues",0));
        System.out.println("Verifica Online false expected (Marca di un docuymento diverso)");
        System.out.println(tsm.verifyOnline("documenti/documento7.txt", "marche/documento8.txt.marca","pubblici/hashValues",0));
        
        //Ripristino della computazione
        TSA TSAserver2 = new TSA("pubblici/hashValues","pubblici/hashValues2");
        TimestampManager tsm2 = new TimestampManager(TSAserver2);
        //Aprendo i file hashValues e hashValues2 si può notare come differiscano solo per gli ultimi due valori 
        //di hash e superhash
        tsm2.generateRequest("keyring/Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento14.txt");
        tsm2.processRequests();   
    }
}
