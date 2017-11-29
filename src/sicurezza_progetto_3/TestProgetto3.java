package sicurezza_progetto_3;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.*;
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
        
        //Generazione keyring di utenti random
        Map<String, char[]> users = new HashMap<>();
        Map<String,String> filesChiaviPrivate = new HashMap<>();
        int usersNumber = 14;
        for(int i = 1; i <= usersNumber; i++){
            users.put("Utente"+i, ("utente"+i).toCharArray());
            filesChiaviPrivate.put("Utente"+i, "keyring/Utente"+ i +".kc");
        }
        users.put("TSA", "TSAPass".toCharArray());
        filesChiaviPrivate.put("TSA", "keyring/TSA.kc");
        KeychainUtils.generateKeyPairs(users, "pubblici/chiaviPub.txt", filesChiaviPrivate);
        
        //Istanziazione TSA e TimeStampManager
        TSA TSAserver = new TSA("pubblici/hashValues");
        TimestampManager tsm = new TimestampManager(TSAserver);
        
        //Genera richieste per file testuali, uno diverso per ogni utente
        for(int i = 1; i <= usersNumber; i ++){
            tsm.generateRequest("keyring/Utente"+ i +".kc", "Utente"+i, ("utente"+i).toCharArray(), "documenti/documento"+i+".txt");
        }
        
        //Genera richieste addizionali per alcuni utenti, con file multimediali
        tsm.generateRequest("keyring/Utente1.kc", "Utente1", "utente1".toCharArray(), "documenti/foto1.jpg");
        tsm.generateRequest("keyring/Utente7.kc", "Utente7", "utente7".toCharArray(), "documenti/lifestyle.mp3");
        tsm.generateRequest("keyring/Utente12.kc", "Utente12", "utente12".toCharArray(), "documenti/foto2.jpg");
        
        //16 richieste sono state processate automaticamente. Per processare l'altra si invoca il metodo sottostante.
        //Test nodi dummy nel MerkleTree
        tsm.processRequests();
        tsm.processRequests(); //Forza timeframe a vuoto. I nodi dummy vengono comunque generati.
        
        //Verifiche online:
        System.out.println("Test verifica online, true expected, controllando tutta la catena");
        int k = 0;
        int verifyLimit = 10;
        for(int i = 1; i <=14; i++){
            if((i-1) % 8 == 0)
                System.out.println("\nTimeFrame: "+(++k)+"\n");
            System.out.println("Verifica "+i+": "+tsm.verifyOnline("documenti/documento"+i+".txt", "marche/documento"+i+".txt.marca", "pubblici/hashValues", verifyLimit));
        }
        System.out.println("Verifica 15: "+tsm.verifyOnline("documenti/foto1.jpg", "marche/foto1.jpg.marca", "pubblici/hashValues", verifyLimit));
        System.out.println("Verifica 16: "+tsm.verifyOnline("documenti/foto2.jpg", "marche/foto2.jpg.marca", "pubblici/hashValues", verifyLimit));
        System.out.println("Timeframe: 3\n");
        tsm.verifyOnline("documenti/lifestyle.mp3", "marche/lifestyle.mp3.marca", "pubblici/hashValues", verifyLimit);
        
        //Verifiche offline:
        System.out.println("Test verifica offline, true expected");
        k = 0;
        for(int i = 1; i <=14; i++){
            if((i-1) % 8 == 0)
                System.out.println("\nTimeFrame: "+(++k)+"\n");
            System.out.println("Verifica "+i+": "+tsm.verifyOffline("documenti/documento"+i+".txt", "marche/documento"+i+".txt.marca"));
        }
        System.out.println("Verifica 15: "+tsm.verifyOffline("documenti/foto1.jpg", "marche/foto1.jpg.marca"));
        System.out.println("Verifica 16: "+tsm.verifyOffline("documenti/foto2.jpg", "marche/foto2.jpg.marca"));
        System.out.println("\nTimeframe: 3\n");
        System.out.println("Verifica 17: "+tsm.verifyOffline("documenti/lifestyle.mp3", "marche/lifestyle.mp3.marca"));

        //Ripristino della computazione
        /*TSA TSAserver2 = new TSA("pubblici/hashValues","pubblici/hashValues2");
        TimestampManager tsm2 = new TimestampManager(TSAserver2);
        //Aprendo i file hashValues e hashValues2 si può notare come differiscano solo per gli ultimi due valori 
        //di hash e superhash
        tsm2.generateRequest("keyring/Mikimix.kc", "Mikimix", "sanremo".toCharArray(), "documenti/documento14.txt");
        tsm2.processRequests(); */  
    }
}
