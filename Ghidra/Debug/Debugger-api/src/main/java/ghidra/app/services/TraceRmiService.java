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
import java.util.Collection;

import ghidra.debug.api.tracermi.*;
import ghidra.framework.plugintool.ServiceInfo;

/**
 * A service (both in the Ghidra framework sense, and in the network sense) for connecting Trace
 * RMI-based back-end debuggers.
 * 
 * <p>
 * This service connects to back-end debuggers, and/or allows back-end debuggers to connect to it.
 * Either way, Ghidra becomes the front-end, acting as the Trace RMI server, and the back-end
 * debugger acts as the Trace RMI client. The Ghidra front-end may also send control commands to the
 * back-end, e.g., to step, resume, or suspend the target.
 */
@ServiceInfo(
	description = "A service for accepting and creating Trace RMI connections",
	defaultProviderName = "ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin")
public interface TraceRmiService {
	/**
	 * Get the address (and port) of the Trace RMI TCP server
	 * 
	 * @return
	 */
	SocketAddress getServerAddress();

	/**
	 * Set the address (and port) of the Trace RMI TCP server
	 * 
	 * @param serverAddress may be null to bind to ephemeral port
	 */
	void setServerAddress(SocketAddress serverAddress);

	/**
	 * Start the Trace RMI TCP server
	 * 
	 * @throws IOException
	 */
	void startServer() throws IOException;

	/**
	 * Stop the Trace RMI TCP server
	 */
	void stopServer();

	/**
	 * Check if the service is listening for inbound connections (other than those expected by
	 * {@link #acceptOne(SocketAddress)}).
	 * 
	 * @return true if listening, false otherwise
	 */
	boolean isServerStarted();

	/**
	 * Assuming a back-end debugger is listening, connect to it.
	 * 
	 * @param address the address (and port) of the back-end system
	 * @return the connection
	 * @throws IOException if the connection failed
	 */
	TraceRmiConnection connect(SocketAddress address) throws IOException;

	/**
	 * Prepare to accept a single connection by listening on the given address.
	 * 
	 * <p>
	 * This essentially starts a server (separate from the one creased by {@link #startServer()})
	 * that will accept a single connection. The server is started by this method. The caller can
	 * then invoke (on the same thread) whatever back-end system or agent that is expected to
	 * connect back to this service. Assuming that system runs in the background, this thread can
	 * then invoke {@link TraceRmiAcceptor#accept()} to actually accept that connection. Once
	 * accepted, the service is terminated, and the server socket is closed. The client socket
	 * remains open.
	 * 
	 * @param address the socket address to bind, or null for ephemeral
	 * @return the acceptor, which can be used to retrieve the ephemeral address and accept the
	 *         actual connection
	 * @throws IOException on error
	 */
	TraceRmiAcceptor acceptOne(SocketAddress address) throws IOException;

	/**
	 * Get all of the active connections
	 * 
	 * @return the connections
	 */
	Collection<TraceRmiConnection> getAllConnections();

	/**
	 * Get all of the acceptors currently listening for a connection
	 * 
	 * @return the acceptors
	 */
	Collection<TraceRmiAcceptor> getAllAcceptors();

	/**
	 * Add a listener for events on the Trace RMI service
	 * 
	 * @param listener the listener to add
	 */
	void addTraceServiceListener(TraceRmiServiceListener listener);

	/**
	 * Remove a listener for events on the Trace RMI service
	 * 
	 * @param listener the listener to remove
	 */
	void removeTraceServiceListener(TraceRmiServiceListener listener);

}
