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
package ghidra.server.remote;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;

import javax.net.ssl.*;

/**
 * <code>GhidraSSLServerSocket</code> facilitates ability to impose client authentication
 * for SSL server sockets used with Ghidra Server RMI connection.
 */
public class GhidraSSLServerSocket extends ServerSocket {

	private static ThreadLocal<Principal> pricipalContext = new ThreadLocal<Principal>();

	/**
	 * Get the peer principal corresponding to the RMI client connection established
	 * with the current thread.
	 * @return RMI client peer principal
	 */
	public static Principal getThreadClientPrincipal() {
		return pricipalContext.get();
	}

	private final SSLSocketFactory sslSocketFactory;
	private final String[] enabledCipherSuites;
	private final String[] enabledProtocols;
	private final boolean needClientAuth;

	/**
	 * Create SSL Server Socket using the default SSLContext
	 * @param port
	 * @param enabledCipherSuites
	 * @param enabledProtocols
	 * @param needClientAuth if true client authentication is required
	 * @throws IOException
	 */
	GhidraSSLServerSocket(int port, String[] enabledCipherSuites, String[] enabledProtocols, boolean needClientAuth)
			throws IOException {
		super(port);
		this.enabledCipherSuites = enabledCipherSuites;
		this.enabledProtocols = enabledProtocols;
		this.needClientAuth = needClientAuth;
		try {
			sslSocketFactory = SSLContext.getDefault().getSocketFactory();
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}

	@Override
	public Socket accept() throws IOException {
		Socket socket = super.accept();

		final SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(socket,
			socket.getInetAddress().getHostAddress(), socket.getPort(), true);
		sslSocket.setUseClientMode(false);
		if (enabledCipherSuites != null) {
			sslSocket.setEnabledCipherSuites(enabledCipherSuites);
		}
		if (enabledProtocols != null) {
			sslSocket.setEnabledProtocols(enabledProtocols);
		}
		sslSocket.setNeedClientAuth(needClientAuth);
		return sslSocket;
	}
}
