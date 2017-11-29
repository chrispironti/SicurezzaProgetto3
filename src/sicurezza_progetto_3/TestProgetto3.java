package sicurezza_progetto_3;

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.*;
import org.json.*;
import java.util.*;

public class TestProgetto3 {
    public static void main(String[] args) throws IOException, InterruptedException{
        System.out.println("Inizio Test.\n");
        //Generazione keyring di utenti random
        int usersNumber = 14;
        System.out.println("Generazione "+ usersNumber +" utenti random...");
        Map<String, char[]> users = new HashMap<>();
        Map<String,String> filesChiaviPrivate = new HashMap<>();
        for(int i = 1; i <= usersNumber; i++){
            users.put("Utente"+i, ("utente"+i).toCharArray());
            filesChiaviPrivate.put("Utente"+i, "keyring/Utente"+ i +".kc");
        }
        users.put("TSA", "TSAPass".toCharArray());
        filesChiaviPrivate.put("TSA", "keyring/TSA.kc");
        KeychainUtils.generateKeyPairs(users, "pubblici/chiaviPub.txt", filesChiaviPrivate);

        //Istanziazione TSA e TimeStampManager
        System.out.println("Inizializzazione server TSA e TimestampManager...");
        TSA TSAserver = new TSA("pubblici/hashValues");
        TimestampManager tsm = new TimestampManager(TSAserver);
        
        //Genera richieste per file testuali, uno diverso per ogni utente
        System.out.println("Generazione di "+(usersNumber+2)+" richieste...");
        for(int i = 1; i <= usersNumber; i ++){
            tsm.generateRequest("keyring/Utente"+ i +".kc", "Utente"+i, ("utente"+i).toCharArray(), "documenti/documento"+i+".txt");
        }
        
        //Genera richieste addizionali per alcuni utenti, con file multimediali
        tsm.generateRequest("keyring/Utente1.kc", "Utente1", "utente1".toCharArray(), "documenti/foto1.jpg");
        tsm.generateRequest("keyring/Utente7.kc", "Utente7", "utente7".toCharArray(), "documenti/lifestyle.mp3");
        
        //Test nodi dummy nel MerkleTree
        System.out.println("Simulazione invio 0 richieste nel timeframe 3...");
        tsm.processRequests(); //Forza timeframe a vuoto. I nodi dummy vengono comunque generati.
        tsm.generateRequest("keyring/Utente12.kc", "Utente12", "utente12".toCharArray(), "documenti/foto2.jpg");
        System.out.println("Simulazione invio 1 richiesta nel timeframe 4...");
        tsm.processRequests(); //Timeframe con una sola richiesta dopo timeframe vuoto
        
        System.out.println("\n*********************************\n");
        
        //Verifiche online:
        System.out.println("Test verifica online, true expected, controllando tutta la catena\n");
        int verifyLimit = 10;
        JSONObject j = null;
        for(int i = 1; i <=14; i++){
            j = DTSUtils.readStamp("marche/documento"+i+".txt.marca");
            System.out.println("Timeframe: "+j.getInt("TF")+", Verifica "+i+": "+tsm.verifyOnline("documenti/documento"+i+".txt", "marche/documento"+i+".txt.marca", "pubblici/hashValues", verifyLimit));
        }
        j = DTSUtils.readStamp("marche/foto1.jpg.marca");
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 15: "+tsm.verifyOnline("documenti/foto1.jpg", "marche/foto1.jpg.marca", "pubblici/hashValues", verifyLimit));
        j = DTSUtils.readStamp("marche/lifestyle.mp3.marca");
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 16: "+tsm.verifyOnline("documenti/lifestyle.mp3", "marche/lifestyle.mp3.marca", "pubblici/hashValues", verifyLimit));
        j = DTSUtils.readStamp("marche/foto2.jpg.marca");
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 17: "+tsm.verifyOnline("documenti/foto2.jpg", "marche/foto2.jpg.marca", "pubblici/hashValues", verifyLimit));
        
        System.out.println("\n*********************************\n");
        
        //Verifiche offline:
        System.out.println("\nTest verifica offline, true expected\n");
        for(int i = 1; i <=14; i++){
            j = DTSUtils.readStamp("marche/documento"+i+".txt.marca");
            System.out.println("Timeframe: "+j.getInt("TF")+", Verifica "+i+": "+tsm.verifyOffline("documenti/documento"+i+".txt", "marche/documento"+i+".txt.marca"));
        }
        j = DTSUtils.readStamp("marche/foto1.jpg.marca");
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 15: "+tsm.verifyOffline("documenti/foto1.jpg", "marche/foto1.jpg.marca"));
        j = DTSUtils.readStamp("marche/lifestyle.mp3.marca");
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 16: "+tsm.verifyOffline("documenti/lifestyle.mp3", "marche/lifestyle.mp3.marca"));
        j = DTSUtils.readStamp("marche/foto2.jpg.marca");
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 17: "+tsm.verifyOffline("documenti/foto2.jpg", "marche/foto2.jpg.marca"));
        
        System.out.println("\n*********************************\n");
        
        /*Alterazioni su verifiche effettuate preliminarmente. Tali
        alterazioni simulano l'inserimento di informazioni non valide da parte
        del server TSA.*/
        System.out.println("\nTest preliminari false expected\n");
        System.out.println("Test alterazione documento originale");
        //Per questo test è sufficiente passare un documento diverso rispetto alla marca
        System.out.println("Verifica 10 dopo alterazione documento originale: "+tsm.verifyOffline("documenti/documento9.txt", "marche/documento10.txt.marca"));
        System.out.println("\nTest falsificazione digest TSA");
        alterUserTimestamp("TSAD", "[0-9]", "3", "marche/documento10.txt.marca");
        System.out.println("Verifica 10 dopo falsificazione digest TSA: "+tsm.verifyOffline("documenti/documento10.txt", "marche/documento10.txt.marca.mod"));
        System.out.println("\nTest alterazione marca e verifica firma");
        alterUserTimestamp("TSAD", "[0-9]", "3", "marche/documento10.txt.marca");
        System.out.println("Verifica firma su documento 10 dopo alterazione marca: "+tsm.verifyTSASign("marche/documento10.txt.marca.mod"));
        System.out.println("Verifica firma su documento 10 senza alterazione marca (true expected): "+tsm.verifyTSASign("marche/documento10.txt.marca"));
        
        System.out.println("\n*********************************\n");
        
        /*Alterazioni al fine di provare che la verifica online fallisce. Tali
        alterazioni simulano l'inserimento di informazioni non valide da parte
        del server TSA.*/
        System.out.println("\nTest verifica online false expected: \n");
        int timeframeToAlter = 2;
        System.out.println("Falsificazione HV("+timeframeToAlter+") della catena");
        alterHashValuesFile("HashValue", "[0-9]", "3", "pubblici/hashValues", timeframeToAlter);
        System.out.println("Verifica 17 online dopo falsificazione HV: "+tsm.verifyOnline("documenti/foto2.jpg", "marche/foto2.jpg.marca", "pubblici/hashValues.mod", verifyLimit));
        Thread.sleep(100); //Attendo chiusura di tutti gli stream
        System.out.println("\nFalsificazione SHV("+timeframeToAlter+") della catena");
        alterHashValuesFile("SuperHashValue", "[0-9]", "3", "pubblici/hashValues", timeframeToAlter);
        System.out.println("Verifica 17 online dopo falsificazione SHV: "+tsm.verifyOnline("documenti/foto2.jpg", "marche/foto2.jpg.marca", "pubblici/hashValues.mod", verifyLimit));
        Thread.sleep(100); //Attendo chiusura di tutti gli stream
        System.out.println("\nFalsificazione HV della marca");
        alterUserTimestamp("HV", "[0-9]", "3", "marche/foto2.jpg.marca");
        System.out.println("Verifica 17 online dopo falsificazione HV della marca: "+tsm.verifyOnline("documenti/foto2.jpg", "marche/foto2.jpg.marca.mod", "pubblici/hashValues", verifyLimit));
        
        System.out.println("\n*********************************\n");
        
        /*Alterazioni al fine di provare che la verifica offline fallisce. Tali
        alterazioni simulano l'inserimento di informazioni non valide da parte
        del server TSA.*/
        System.out.println("\nTest verifica offline false expected: \n");
        System.out.println("Falsificazione HV della marca");
        alterUserTimestamp("HV", "[0-9]", "3", "marche/documento1.txt.marca");
        System.out.println("Verifica 1 offline dopo falsificazione HV della marca: "+tsm.verifyOffline("documenti/documento1.txt", "marche/documento1.txt.marca.mod"));
        System.out.println("\nFalsificazione Verify Information della marca");
        alterUserTimestamp("VI", "[0-9]", "3", "marche/documento1.txt.marca");
        System.out.println("Verifica 1 offline dopo falsificazione verify information della marca: "+tsm.verifyOffline("documenti/documento1.txt", "marche/documento1.txt.marca.mod"));
        
        System.out.println("\n*********************************\n");
        
        //Test ripristino della computazione
        System.out.println("\nTest istanziazione di un nuovo server TSA, che ripartirà da dove si era fermato il precedente.");
        System.out.println("\nInizializzazione nuovo TSA e TimestampManager...");
        TSA TSAserver2 = new TSA("pubblici/hashValues","pubblici/hashValues2");
        TimestampManager tsm2 = new TimestampManager(TSAserver2);
        System.out.println("Generazione nuova richiesta...");
        tsm2.generateRequest("keyring/Utente3.kc", "Utente3", "utente3".toCharArray(), "documenti/timestamping.pdf");
        tsm2.processRequests();
        System.out.println("\nVerifica offline e online nuova richiesta (true expected):\n");
        j = DTSUtils.readStamp("marche/timestamping.pdf.marca");
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 18: "+tsm.verifyOffline("documenti/timestamping.pdf", "marche/timestamping.pdf.marca"));
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 18: "+tsm.verifyOnline("documenti/timestamping.pdf", "marche/timestamping.pdf.marca", "pubblici/hashValues2", verifyLimit));
        System.out.println("\nVerifica offline e online vecchia richiesta (true expected):\n");
        j = DTSUtils.readStamp("marche/foto1.jpg.marca");
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 15: "+tsm.verifyOffline("documenti/foto1.jpg", "marche/foto1.jpg.marca"));
        System.out.println("Timeframe: "+j.getInt("TF")+", Verifica 15: "+tsm.verifyOnline("documenti/foto1.jpg", "marche/foto1.jpg.marca", "pubblici/hashValues2", verifyLimit));
        System.out.println("\nConfronto vecchio e nuovo file degli hashValue: devono essere diversi.");
        Path p = Paths.get("pubblici/hashValues");
        String oldf = new String(Files.readAllBytes(p));
        p = Paths.get("pubblici/hashValues2");
        String newf = new String(Files.readAllBytes(p));
        System.out.println(oldf.compareTo(newf) == 0);
        System.out.println("\nFine Test.");
    }
    
    public static void alterHashValuesFile(String fieldToAlter, String regex, String replace, String hashFile, int timeframe) throws IOException{
        
        //Alterazione campo
        JSONArray ja = DTSUtils.readHashValues(hashFile);
        JSONObject j = ja.getJSONObject(timeframe);
        j.put(fieldToAlter, j.getString(fieldToAlter).replaceAll(regex, replace));
        ja.put(timeframe, j);
        //Salvataggio
        BufferedWriter bw = null;
        try{
            bw = new BufferedWriter(new FileWriter(hashFile+".mod"));
            bw.write(ja.toString());
        }finally{
            bw.close();
        }
    }
    
    public static void alterUserTimestamp(String fieldToAlter, String regex, String replace, String marcaFile) throws IOException{
        
        JSONObject j = DTSUtils.readStamp(marcaFile);
        j.put(fieldToAlter, j.getString(fieldToAlter).replaceAll(regex, replace));
        BufferedOutputStream bos = null;
        try{
            bos = new BufferedOutputStream(new FileOutputStream(marcaFile+".mod"));
            bos.write(j.toString().getBytes("UTF8"));
        }finally{
            bos.close();
        }
    }
}
