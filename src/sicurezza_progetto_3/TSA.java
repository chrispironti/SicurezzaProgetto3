/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.sql.Timestamp;
import java.security.*;
import javax.crypto.*;
import org.json.*;

/**
 * Implementa i meccanismi per accettare e rispondere a richieste di Timestamp.
 */

public class TSA {
    
    private final String hashAlgorithm = "SHA-256";
    private int serialNumber;
    private int timeframe;
    private MerkleTree mt; 
    private JSONArray hashValues;
    private String hashFile;
    private Keychain TSAKeyChain;
    private MessageDigest md;
    private final int DUMMYSIZE = 10;

    
    public TSA(String hashFileToWrite) throws IOException{
        
        this.serialNumber = 0;
        this.hashFile=hashFileToWrite;
        this.timeframe = 0;
        this.hashValues = new JSONArray();
        this.TSAKeyChain = new Keychain("keyring/TSA.kc","TSAPass".toCharArray());
        try {
            this.md = MessageDigest.getInstance(this.hashAlgorithm);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
        computeHashValues();
    }
    
    public TSA(String hashFileToRead, String hashFileToWrite ) throws IOException{
        
        this.hashValues = new JSONArray(new String(Files.readAllBytes(Paths.get(hashFileToRead)),"UTF-8"));
        this.hashFile=hashFileToWrite;
        this.timeframe = this.hashValues.length() -1;
        this.serialNumber = 8*this.timeframe;
        this.TSAKeyChain = new Keychain("keyring/TSA.kc","TSAPass".toCharArray());
        try {
            this.md = MessageDigest.getInstance(this.hashAlgorithm);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }
    
    public ArrayList<TSAMessage> generateTimestamp(ArrayList<TSAMessage> requests) throws IOException{
        
        try {
            this.mt = new MerkleTree();
        } catch (NoSuchAlgorithmException ex) {
           ex.printStackTrace();
           System.exit(1);
        }finally{
            saveHashValues();
        }
        this.timeframe += 1;
        ArrayList<JSONObject> partialResponses = createResponses(requests);
        computeHashValues();
        ArrayList<String> merkleInfo = mt.buildInfo();
        saveHashValues();
        return finalizeResponses(partialResponses, merkleInfo);  
    }
    
    private JSONObject makeResponseInfo(JSONObject userInfo){  
        
        JSONObject responseInfo = new JSONObject();
        String t = new Timestamp(System.currentTimeMillis()+10000*this.serialNumber).toString(); 
        responseInfo.put("TS", t);
        responseInfo.put("ID", userInfo.getString("ID"));
        responseInfo.put("SN", this.serialNumber);
        String messageDigest = userInfo.getString("MD");
        responseInfo.put("MD",messageDigest);
        byte[] userMessageDigest = Base64.getDecoder().decode(messageDigest);
        byte[] timestamp = t.getBytes();
        this.mt.insert(userMessageDigest, timestamp);
        this.md.update(DTSUtils.arrayConcat(userMessageDigest, timestamp));
        responseInfo.put("TSAD",Base64.getEncoder().encodeToString(this.md.digest()));
        responseInfo.put("TF", this.timeframe);
        return responseInfo;
    }
    
    private ArrayList<JSONObject> createResponses(ArrayList<TSAMessage> requests) throws IOException{
        
        PrivateKey rsaprivKey = this.TSAKeyChain.getPrivateKey("Key/RSA/2048/Main");
        ArrayList<JSONObject> partialResponses = new ArrayList<>();
        Cipher c = null;
        try {
            c = Cipher.getInstance("RSA/ECB/OAEPPadding");
            c.init(Cipher.DECRYPT_MODE, rsaprivKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            ex.printStackTrace();
            System.exit(1);
        } finally {
            saveHashValues();
        }
        
        int requestNumber = 0;
        /*Esamino le richieste, decifro, verifico la firma e creo i JSONObject di risposta
        da completare con le informazioni derivanti dalla costruzione del Merkel Tree
        */
        for(TSAMessage m: requests){          
                
            try{
                    requestNumber += 1;
                    this.serialNumber += 1;
                    byte[] decrypted = c.doFinal(m.getInfo());
                    JSONObject userInfo = new JSONObject(new String(decrypted,"UTF8"));
                    PublicKey dsapubKey = PublicKeysManager.getPublicKeysManager().getPublicKey(userInfo.getString("ID"), "Key/DSA/2048/Main");
                    DTSUtils.verifyText(decrypted, m.getSign(), dsapubKey);
                    JSONObject responseInfo = makeResponseInfo(userInfo);
                    partialResponses.add(responseInfo);
                } catch (IllegalBlockSizeException | BadPaddingException | SignatureException | UnsupportedEncodingException | NotVerifiedSignException | NoSuchAlgorithmException | InvalidKeyException ex) {
                    System.out.println("Errore. Impossibile processare richiesta numero " + requestNumber + 
                            " del timeframe " +this.timeframe+". La richiesta verrà ignorata.");
                    partialResponses.add(null);
            }
        }
        /*Se ci sono meno di 8 richieste (ne sono arrivate meno di 8 o alcune sono
        state scartate), completa il merkel tree con nodi fittizi*/
        SecureRandom sr = new SecureRandom();
        while (mt.getSize() < 8){
            byte[] dummy = new byte[this.DUMMYSIZE];
            sr.nextBytes(dummy);
            this.md.update(dummy);
            String t = new Timestamp(System.currentTimeMillis()+10000*this.serialNumber).toString();
            this.mt.insert(this.md.digest(), t.getBytes("UTF8"));
            this.serialNumber += 1;
        }
        return partialResponses;
    }
    
    private ArrayList<TSAMessage> finalizeResponses(ArrayList<JSONObject> partialResponses, ArrayList<String> merkleInfo) throws IOException{
        
        Iterator<String> i = merkleInfo.iterator();
        ArrayList<TSAMessage> responses = new ArrayList<>();
            for(JSONObject j: partialResponses){
                if (j != null){
                    j.put("VI", i.next());
                    j.put("HV", getHashValue(this.timeframe));
                    PrivateKey dsaprivkey = this.TSAKeyChain.getPrivateKey("Key/DSA/2048/Main");
                    responses.add(new TSAMessage(j, dsaprivkey));
                }else{
                    responses.add(null);
                }
            }           
        return responses;
    }
    
    private void computeHashValues() throws IOException{
        
        byte[] shv_i = null;
        JSONObject j = new JSONObject();
        if (this.timeframe == 0){
            SecureRandom sr = new SecureRandom();
            shv_i = new byte[this.DUMMYSIZE];
            sr.nextBytes(shv_i);
        }else{
            byte[] hv = null;
            try {
                hv = mt.buildMerkleTree();
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
                System.exit(1);
            }finally{
                saveHashValues();
            }
            String superHashValue = this.hashValues.getJSONObject(this.timeframe-1).getString("SuperHashValue");
            byte[] shv_before = Base64.getDecoder().decode(superHashValue);
            shv_i = DTSUtils.arrayConcat(shv_before, hv);
            j.put("HashValue", Base64.getEncoder().encodeToString(hv));
        }            
        this.md.update(shv_i);
        j.put("SuperHashValue", Base64.getEncoder().encodeToString(this.md.digest()));
        this.hashValues.put(this.timeframe, j);
    }
    
    public String getHashValue(int timeframe){
        
        if (timeframe == 0){
            System.out.println("Errore. Nessun Hash Value al timeframe 0.");
            return null;
        }
        else{
            JSONObject j = this.hashValues.getJSONObject(timeframe);
            return j.getString("HashValue");
        }
    }
    
    public String getSuperHashValue(int timeframe){
        
        JSONObject j = this.hashValues.getJSONObject(timeframe);
        return j.getString("SuperHashValue");
    }   
    
    
    private void saveHashValues() throws IOException{
        
        BufferedWriter bw = null;
        try{
            bw = new BufferedWriter( new FileWriter(this.hashFile));
            bw.write(this.hashValues.toString());
        }finally{
            bw.close();
        }
    }
}