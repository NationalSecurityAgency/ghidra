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
package ghidra.app.services;

import java.io.IOException;
import java.net.SocketAddress;

import ghidra.app.plugin.core.debug.service.rmi.trace.TraceRmiAcceptor;
import ghidra.app.plugin.core.debug.service.rmi.trace.TraceRmiHandler;

public interface TraceRmiService {
	SocketAddress getServerAddress();

	/**
	 * Set the server address and port
	 * 
	 * @param serverAddress may be null to bind to ephemeral port
	 */
	void setServerAddress(SocketAddress serverAddress);

	void startServer() throws IOException;

	void stopServer();

	boolean isServerStarted();

	TraceRmiHandler connect(SocketAddress address) throws IOException;

	/**
	 * Accept a single connection by listening on the given address
	 * 
	 * @param address the socket address to bind, or null for ephemeral
	 * @return the acceptor, which can be used to retrieve the ephemeral address and accept the
	 *         actual connection
	 * @throws IOException on error
	 */
	TraceRmiAcceptor acceptOne(SocketAddress address) throws IOException;
}
