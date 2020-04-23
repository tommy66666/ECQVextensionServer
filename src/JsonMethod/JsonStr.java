package JsonMethod;

import Person.personbean;
import java.util.List;

/**
 *
 * @author Legend-novo
 */
public class JsonStr {
    public static String getJson(List<personbean> person){
        if(person.isEmpty()){
        System.out.println("传入对象为空！");
        }else{
        StringBuilder json = new StringBuilder();
        if (person.size()==1) {
                json.append("{\"name\":\"");
                json.append(person.get(0).getName());
                json.append("\",\"age\":\"");
                json.append(person.get(0).getAge());
                json.append("\"}");
        }else {
                json.append("[");
                for (int i = 0; i < person.size(); i++) {
                json.append("{\"name\":\"");
                json.append(person.get(i).getName());
                json.append("\",\"age\":\"");
                json.append(person.get(i).getAge());
                if (i <(person.size()-1)) {
                        json.append("\"},");
                }else {
                        json.append("\"}");
                }
          }
                json.append("]");
        }
        return json.toString();
        }
        return null;
    }
}
