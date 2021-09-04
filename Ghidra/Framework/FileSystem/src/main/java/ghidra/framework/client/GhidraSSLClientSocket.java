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
package ghidra.framework.client;

import java.io.IOException;
import java.net.*;
import java.util.*;

import javax.net.ssl.*;
import javax.rmi.ssl.SslRMIClientSocketFactory;

/**
 * <code>GhidraSSLClientSocket</code> facilitates ability to impose client authentication
 * for SSL server sockets used with Ghidra Server RMI connection.
 */
public class GhidraSSLClientSocket extends SslRMIClientSocketFactory {
	/**
	 * Creates an SSLSocket on a given port
	 *
	 * @throws IOException if an error occurs on socket creation.
	 */
	public Socket createSocket(String host, int port) throws IOException
	{
		SSLSocket sslSocket = (SSLSocket) super.createSocket(host, port);
		List<SNIServerName> serverNames = Arrays.asList(new SNIHostName(host));
		SSLParameters params = sslSocket.getSSLParameters();
		params.setServerNames(serverNames);
		sslSocket.setSSLParameters(params);
		return sslSocket;
	}
}
