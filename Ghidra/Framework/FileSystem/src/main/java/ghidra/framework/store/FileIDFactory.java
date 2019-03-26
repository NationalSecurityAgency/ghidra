/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.store;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

import javax.net.ServerSocketFactory;

/**
 * Factory class for generating unique file ID's.
 */
public class FileIDFactory {
	
	private FileIDFactory() {
	}
	
	public static String createFileID()  {
		try {
			// Ensure time uniqueness within process
			Thread.sleep(2);
		} catch (InterruptedException e1) {
		}
		int uniquePort = 0;
		byte[] addrBytes = null;
		ServerSocket serverSocket = null;
		try {
			StringBuffer buf = new StringBuffer();
			serverSocket = ServerSocketFactory.getDefault().createServerSocket();
			serverSocket.bind(null);
			uniquePort = serverSocket.getLocalPort();
			addrBytes = InetAddress.getLocalHost().getAddress();
			for (int i = 0; i < 4; i++) {
				int b = addrBytes[i] & 0xff;
				buf.append(Integer.toHexString(b));
			}
			buf.append(Integer.toHexString(uniquePort));
			buf.append(System.nanoTime());
			return buf.toString();
		} catch (IOException e) {
		} finally {
			if (serverSocket != null) {
				try {
					serverSocket.close();
				} catch (IOException e) {
				}
			}
		}
		
		// We do not have a network interface :( 
		// TODO: this case could use improvement - possible exposure is use of shared project in an off-line mode
		return Long.toHexString(System.nanoTime());
	}

}
