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
import java.util.Collection;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeoutException;

import ghidra.debug.api.target.Target;
import ghidra.trace.model.Trace;

/**
 * A connection to a TraceRmi back end
 *
 * <p>
 * TraceRmi is a two-way request-reply channel, usually over TCP. The back end, i.e., the trace-rmi
 * plugin hosted in the target platform's actual debugger, is granted a fixed set of
 * methods/messages for creating and populating a {@link Trace}. Each such trace is designated as a
 * target. The back end provides a set of methods for the front-end to use to control the connection
 * and its targets. For a given connection, the methods are fixed, but each back end may provide a
 * different set of methods to best describe/model its command set. The same methods are applicable
 * to all of the back end's target. While uncommon, one back end may create several targets. E.g.,
 * if a target creates a child process, and the back-end debugger is configured to remain attached
 * to both parent and child, then it should create and publish a second target.
 */
public interface TraceRmiConnection extends AutoCloseable {
	/**
	 * Get the client-given description of this connection
	 * 
	 * <p>
	 * If the connection is still being negotiated, this will return a string indicating that.
	 * 
	 * @return the description
	 */
	String getDescription();

	/**
	 * Get the address of the back end debugger
	 * 
	 * @return the address, usually IP of the host and port for the trace-rmi plugin.
	 */
	SocketAddress getRemoteAddress();

	/**
	 * Get the methods provided by the back end
	 * 
	 * @return the method registry
	 */
	RemoteMethodRegistry getMethods();

	/**
	 * Wait for the first trace created by the back end.
	 * 
	 * <p>
	 * Typically, a connection handles only a single target. A shell script handles launching the
	 * back-end debugger, creating its first target, and connecting back to the front end via
	 * TraceRmi. If a secondary target does appear, it usually happens only after the initial target
	 * has run. Thus, this method is useful for waiting on and getting and handle to that initial
	 * target.
	 * 
	 * @param timeoutMillis the number of milliseconds to wait for the target
	 * @return the trace
	 * @throws TimeoutException if no trace is created after the given timeout. This usually
	 *             indicates there was an error launching the initial target, e.g., the target's
	 *             binary was not found on the target's host.
	 */
	Trace waitForTrace(long timeoutMillis) throws TimeoutException;

	/**
	 * Get the last snapshot created by the back end for the given trace.
	 * 
	 * <p>
	 * Back ends that support timeless or time-travel debugging have not been integrated yet, but in
	 * those cases, we anticipate this method returning the current snapshot (however the back end
	 * defines that with respect to its own definition of time), whether or not it is the last
	 * snapshot it created. If the back end has not created a snapshot yet, 0 is returned.
	 * 
	 * @param trace
	 * @return the snapshot number
	 * @throws NoSuchElementException if the given trace is not a target for this connection
	 */
	long getLastSnapshot(Trace trace);

	/**
	 * Forcefully remove the given trace from the connection.
	 * 
	 * <p>
	 * This removes the back end's access to the given trace and removes this connection from the
	 * trace's list of consumers (thus, freeing it if this was the only remaining consumer.) For all
	 * intents and purposes, the given trace is no longer a target for this connection.
	 * 
	 * <p>
	 * <b>NOTE:</b> This method should only be used if gracefully killing the target has failed. In
	 * some cases, it may be better to terminate the entire connection (See {@link #close()}) or to
	 * terminate the back end debugger. The back end gets no notification that its trace was
	 * forcefully removed. However, subsequent requests involving that trace will result in errors.
	 * 
	 * @param trace the trace to remove
	 */
	void forceCloseTrace(Trace trace);

	/**
	 * Close the TraceRmi connection.
	 * 
	 * <p>
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Upon closing, all the connection's targets (there's usually only one) will be withdrawn and
	 * invalidated.
	 */
	@Override
	void close() throws IOException;

	/**
	 * Check if the connection has been closed
	 * 
	 * @return true if closed, false if still open/valid
	 */
	boolean isClosed();

	/**
	 * Wait for the connection to become closed.
	 * 
	 * <p>
	 * This is usually just for clean-up purposes during automated testing.
	 */
	void waitClosed();

	/**
	 * Check if the given trace represents one of this connection's targets.
	 * 
	 * @param trace the trace
	 * @return true if the trace is a target, false otherwise.
	 */
	boolean isTarget(Trace trace);

	/**
	 * Get all the valid targets created by this connection
	 * 
	 * @return the collection of valid targets
	 */
	Collection<Target> getTargets();
}
