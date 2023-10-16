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
package ghidra.debug.api.tracermi;

import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketException;

/**
 * An acceptor to receive a single Trace RMI connection from a back-end
 */
public interface TraceRmiAcceptor {
	/**
	 * Accept a single connection
	 * 
	 * <p>
	 * This acceptor is no longer valid after the connection is accepted.
	 * 
	 * @return the connection, if successful
	 * @throws IOException if there was an error
	 */
	TraceRmiConnection accept() throws IOException;

	/**
	 * Get the address (and port) where the acceptor is listening
	 * 
	 * @return the socket address
	 */
	SocketAddress getAddress();

	/**
	 * Set the timeout
	 * 
	 * @param millis the number of milliseconds after which an {@link #accept()} will time out.
	 * @throws SocketException if there's a protocol error
	 */
	void setTimeout(int millis) throws SocketException;
}
