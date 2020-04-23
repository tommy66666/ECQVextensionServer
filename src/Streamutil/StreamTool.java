package Streamutil;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 *
 * @author Legend-novo
 */
public class StreamTool {
    	/**
	 * 读取流中的数据
	 * @param stream 传入的流
	 * @return
	 * @throws Exception
	 */
	public static byte[] read(InputStream stream) throws Exception {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int len = 0;
		while((len=stream.read(buffer)) != -1){
			outputStream.write(buffer, 0, len);
		}
		return outputStream.toByteArray();
	}
}
