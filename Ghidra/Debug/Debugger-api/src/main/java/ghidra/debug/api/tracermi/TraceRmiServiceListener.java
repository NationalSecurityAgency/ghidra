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

import java.net.SocketAddress;

import ghidra.app.services.TraceRmiService;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.TargetPublicationListener;

/**
 * A listener for Trace RMI Service events
 */
public interface TraceRmiServiceListener {
	/**
	 * The mechanism for creating a connection
	 */
	enum ConnectMode {
		/**
		 * The connection was established via {@link TraceRmiService#connect(SocketAddress)}
		 */
		CONNECT,
		/**
		 * The connection was established via {@link TraceRmiService#acceptOne(SocketAddress)}
		 */
		ACCEPT_ONE,
		/**
		 * The connection was established by the server. See {@link TraceRmiService#startServer()}
		 */
		SERVER;
	}

	/**
	 * The server has been started on the given address
	 * 
	 * @param address the server's address
	 */
	default void serverStarted(SocketAddress address) {
	}

	/**
	 * The server has been stopped
	 */
	default void serverStopped() {
	}

	/**
	 * A new connection has been established
	 * 
	 * @param connection the new connection
	 * @param mode the mechanism creating the connection
	 * @param if by {@link TraceRmiService#acceptOne(SocketAddress)}, the acceptor that created this
	 *            connection
	 */
	default void connected(TraceRmiConnection connection, ConnectMode mode,
			TraceRmiAcceptor acceptor) {
	}

	/**
	 * A connection was lost or closed
	 * 
	 * <p>
	 * <b>TODO</b>: Do we care to indicate why?
	 * 
	 * @param connection the connection that has been closed
	 */
	default void disconnected(TraceRmiConnection connection) {
	}

	/**
	 * The service is waiting for an inbound connection
	 * 
	 * <p>
	 * The acceptor remains valid until one of three events occurs:
	 * {@linkplain} #connected(TraceRmiConnection, ConnectMode, TraceRmiAcceptor)},
	 * {@linkplain} #acceptCancelled(TraceRmiAcceptor)}, or {@linkplain} #acceptFailed(Exception)}.
	 * 
	 * @param acceptor the acceptor waiting
	 */
	default void waitingAccept(TraceRmiAcceptor acceptor) {
	}

	/**
	 * The client cancelled an inbound acceptor via {@link TraceRmiAcceptor#cancel()}
	 * 
	 * @param acceptor the acceptor that was cancelled
	 */
	default void acceptCancelled(TraceRmiAcceptor acceptor) {
	}

	/**
	 * The service failed to complete an inbound connection
	 * 
	 * @param acceptor the acceptor that failed
	 * @param e the exception causing the failure
	 */
	default void acceptFailed(TraceRmiAcceptor acceptor, Exception e) {
	}

	/**
	 * A new target was created by a Trace RMI connection
	 * 
	 * <p>
	 * The added benefit of this method compared to the {@link TargetPublicationListener} is that it
	 * identifies <em>which connection</em>
	 * 
	 * @param connection the connection creating the target
	 * @param target the target
	 * @see TargetPublicationListener#targetPublished(Target)
	 * @see TargetPublicationListener#targetWithdrawn(Target)
	 */
	default void targetPublished(TraceRmiConnection connection, Target target) {
	}
}
