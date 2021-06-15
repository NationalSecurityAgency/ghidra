/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.net.http;

import java.util.Properties;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;

public class HttpUtilTest {
	public static void main(String[] args) {

		Properties properties = new Properties();
		properties.setProperty("User-Agent", "Microsoft-Symbol-Server/6.3.9600.17298");

		String urlStr =
			"http://msdl.microsoft.com/download/symbols/write.pdb/4FD8CA6696F445A7B969AB9BBD76E4591/write.pd_";

		String homeDir = System.getProperty("user.home");
		File f = new File(homeDir + "/Downloads", "write.pdb.deleteme");

		try {
			HttpUtil.getFile(urlStr, properties, true, f);
			System.out.println("getFile completed: " + f);
		}
		catch (MalformedURLException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

}
