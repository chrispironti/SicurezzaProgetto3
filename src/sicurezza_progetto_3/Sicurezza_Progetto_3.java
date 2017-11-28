/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
 import java.sql.Timestamp;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import org.json.*;
/**
 *
 * @author Daniele
 */
public class Sicurezza_Progetto_3 {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnsupportedEncodingException, FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        // TODO code application logic here
        String str = "documenti/documento1.txt";
        System.out.println("marche/"+str.split("/")[1]+".marca");
    }   
}
