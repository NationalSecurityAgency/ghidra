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
package ghidra.net;

import java.io.IOException;
import java.net.*;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import ghidra.util.Msg;

/**
 * <code>ApplicationSSLSocketFactory</code> provides a replacement for the default
 * <code>SSLSocketFactory</code> which utilizes the default SSLContext established
 * by {@link SSLContextInitializer}.
 */
public class ApplicationSSLSocketFactory extends SSLSocketFactory {

	private final SSLSocketFactory socketFactory;

	/**
	 * ApplicationSSLSocketFactory constructor.  
	 * SSLContext initialization will be performed using {@link SSLContextInitializer}.
	 */
	public ApplicationSSLSocketFactory() {
		SSLSocketFactory factory = null;
		try {
			if (SSLContextInitializer.initialize()) {
				factory = SSLContext.getDefault().getSocketFactory();
			}
		}
		catch (NoSuchAlgorithmException e) {
			Msg.error(this, "Failed to employ default SSLContext: " + e.toString(), e);
		}
		this.socketFactory =
			factory != null ? factory : (SSLSocketFactory) SSLSocketFactory.getDefault();
	}

	@Override
	public Socket createSocket(Socket s, String host, int port, boolean autoClose)
			throws IOException {
		return socketFactory.createSocket(s, host, port, autoClose);
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return socketFactory.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return socketFactory.getSupportedCipherSuites();
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
		return socketFactory.createSocket(host, port);
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		return socketFactory.createSocket(host, port);
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException, UnknownHostException {
		return socketFactory.createSocket(host, port, localHost, localPort);
	}

	@Override
	public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
			int localPort)
			throws IOException {
		return socketFactory.createSocket(address, port, localAddress, localPort);
	}
}
