package Httputil;

import IPsite.IPaddress;
import Streamutil.StreamTool;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Legend-novo
 */
public class HttpMethod {
    
    /**
     * GET方式获取字符串
     * @return  返回字符串
     * @throws Exception 
     */
	public static String getGETString() throws Exception{
		URL url = new URL(IPaddress.IP_get_SITE);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setConnectTimeout(5000);
		conn.setRequestMethod("GET");
                conn.setDoOutput(true);
                conn.setDoInput(true);
		if (conn.getResponseCode() == 200) {
			InputStream inputStream = conn.getInputStream();
			byte[] data = StreamTool.read(inputStream);
			return new String(data);
		}
		return null;
	}
	
	
	
	/**
	 *new get function
	 */
	public static String GETreq(Integer num,String encoding) throws Exception{
		StringBuilder url = new StringBuilder(IPaddress.IP_send_SITE);
		url.append("?");
		url.append("num").append("=");
		url.append(num.toString());
		//url.deleteCharAt(url.length()-1);
		//
		System.out.println(url);
		//
		HttpURLConnection conn = (HttpURLConnection) new URL(url.toString()).openConnection();
		conn.setConnectTimeout(5000);
		conn.setRequestMethod("GET");
		if (conn.getResponseCode() == 200) {
			InputStream inputStream = conn.getInputStream();
			byte[] data = StreamTool.read(inputStream);
			return new String(data);
		}
		return null;
        }
	
        /**
         * 以GET方式发送字符串
         * @param params 要发送的数组
         * @param encoding  发送的编码
         * @return  true返回成功，false返回失败
         * @throws Exception 
         */
        public static String sendGETString(HashMap<String,String> params,String encoding) throws Exception{
		StringBuilder url = new StringBuilder(IPaddress.IP_send_SITE);
		url.append("?");
		for (Map.Entry<String,String> entry: params.entrySet()) {
			url.append(entry.getKey()).append("=");
			url.append(URLEncoder.encode(entry.getValue(), encoding));
			url.append("&");
		}
		url.deleteCharAt(url.length()-1);
		//
		System.out.println(url);
		//
		HttpURLConnection conn = (HttpURLConnection) new URL(url.toString()).openConnection();
		conn.setConnectTimeout(5000);
		conn.setRequestMethod("GET");
		if (conn.getResponseCode() == 200) {
			InputStream inputStream = conn.getInputStream();
			byte[] data = StreamTool.read(inputStream);
			return new String(data);
		}
		return null;
        }
        
     /**
     * POST方式获取字符串
     * @return  返回字符串
     * @throws Exception 
     */
	public static String getPOSTString() throws Exception{
		URL url = new URL(IPaddress.IP_get_SITE);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setConnectTimeout(5000);
		conn.setRequestMethod("POST");
                conn.setRequestProperty("Proxy-Connection", "Keep-Alive");
                conn.setDoOutput(true);
                conn.setDoInput(true);
		if (conn.getResponseCode() == 200) {
			InputStream inputStream = conn.getInputStream();
			byte[] data = StreamTool.read(inputStream);
			return new String(data);
		}
		return null;
	}
        /**
         * 以POST方式发送字符串
         * @param params 要发送的数组
         * @param encoding  发送的编码
         * @return  true返回成功，false返回失败
         * @throws Exception 
         */
        public static boolean  sendPOSTString(HashMap<String,String> params,String encoding) throws Exception{
        StringBuilder data = new StringBuilder();
        if (params != null && !params.isEmpty()) {
                for (Map.Entry<String,String> entry: params.entrySet()) {
                        data.append(entry.getKey()).append("=");
                        data.append(URLEncoder.encode(entry.getValue(), encoding));
                        data.append("&");
                }
                data.deleteCharAt(data.length()-1);
        }
        byte[] entity = data.toString().getBytes();//得到实体数据
        HttpURLConnection conn = (HttpURLConnection) new URL(IPaddress.IP_send_SITE).openConnection();
        conn.setConnectTimeout(5000);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);//允许对外输出数据
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Content-Length", String.valueOf(entity.length));
        OutputStream oStream = conn.getOutputStream();
        oStream.write(entity);
        if(conn.getResponseCode() == 200){//用于获得返回数据才能发送数据，不然数据一直在缓存数据中
                return true;
        }
        return false;
}
}