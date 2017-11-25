/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.io.Serializable;
import org.json.*;

/**
 *
 * @author gennaroavitabile
 */
public class SERJSONObject extends JSONObject implements Serializable{
    
    public SERJSONObject(){
        super();
    }
    
    public SERJSONObject(String s){
        super(s);
    }
    
    public SERJSONObject(JSONObject jo, String[] names){
        super(jo,names);
    }
    
    public SERJSONObject(JSONTokener x){
        super(x);
    }
    
    public SERJSONObject(java.util.Map<?,?> map){
        super(map);
    }
    
    public SERJSONObject(java.lang.Object bean){
        super(bean);
    }
    
    public SERJSONObject(java.lang.String baseName, java.util.Locale locale){
        super(baseName,locale);
    }
}
