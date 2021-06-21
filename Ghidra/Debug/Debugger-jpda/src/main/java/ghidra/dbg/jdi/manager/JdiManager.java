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
package ghidra.dbg.jdi.manager;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.tuple.Pair;

import com.sun.jdi.VirtualMachine;
import com.sun.jdi.VirtualMachineManager;
import com.sun.jdi.connect.Connector;
import com.sun.jdi.connect.Connector.Argument;

import ghidra.dbg.jdi.manager.impl.JdiManagerImpl;

/**
 * The controlling side of a JDI session
 */
public interface JdiManager extends AutoCloseable {

	public enum Channel {
		STDOUT, STDERR;
	}

	/**
	 * Get a new manager instance, without starting JDI
	 * 
	 * @return the manager
	 */
	public static JdiManager newInstance() {
		return new JdiManagerImpl();
	}

	/**
	 * Terminates JDI
	 */
	@Override
	default void close() {
		terminate();
	}

	/**
	 * Terminate JDI
	 */
	void terminate();

	/**
	 * Add a listener for JDI's state
	 * 
	 * @see #getState()
	 * @param vm the virtual machine
	 * @param listener the listener to add
	 */
	void addStateListener(VirtualMachine vm, JdiStateListener listener);

	/**
	 * Remove a listener for JDI's state
	 * 
	 * @see #getState()
	 * @param vm the virtual machine
	 * @param listener the listener to remove
	 */
	void removeStateListener(VirtualMachine vm, JdiStateListener listener);

	/**
	 * Add a listener for events on inferiors
	 * 
	 * @param vm the virtual machine
	 * @param listener the listener to add
	 */
	void addEventsListener(VirtualMachine vm, JdiEventsListener listener);

	/**
	 * Remove a listener for events on inferiors
	 * 
	 * @param vm the virtual machine
	 * @param listener the listener to remove
	 */
	void removeEventsListener(VirtualMachine vm, JdiEventsListener listener);

	/**
	 * Add a listener for target output
	 * 
	 * @param listener the listener to add
	 */
	void addTargetOutputListener(JdiTargetOutputListener listener);

	/**
	 * Remove a listener for target output
	 * 
	 * @see #addTargetOutputListener(JdiTargetOutputListener)
	 * @param listener
	 */
	void removeTargetOutputListener(JdiTargetOutputListener listener);

	/**
	 * Add a listener for console output
	 * 
	 * @param listener the listener to add
	 */
	void addConsoleOutputListener(JdiConsoleOutputListener listener);

	/**
	 * Remove a listener for console output
	 * 
	 * @param listener
	 */
	void removeConsoleOutputListener(JdiConsoleOutputListener listener);

	/**
	 * Get an inferior by its JDI-assigned ID
	 * 
	 * JDI numbers virtual machines incrementally. All vms and created and destroyed by the user.
	 * See {@link #getVM()}.
	 * 
	 * @param iid the inferior ID
	 * @return a handle to the inferior, if it exists
	 */
	VirtualMachine getVM(String id);

	/**
	 * Get all inferiors known to the manager
	 * 
	 * This does not ask JDI to list its inferiors. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of JDI events.
	 * 
	 * @return a map of inferior IDs to corresponding inferior handles
	 */
	Map<String, VirtualMachine> getKnownVMs();

	/**
	 * Send an interrupt to JDI regardless of other queued commands
	 * 
	 * This may be useful if the manager's command queue is stalled because an inferior is running.
	 * 
	 * @throws IOException if an I/O error occurs
	 * @throws InterruptedException
	 */
	void sendInterruptNow() throws IOException;

	/**
	 * Add a virtual machine
	 * 
	 * @param cx Connector specifying how to access the vm
	 * @param args start-up parameters
	 * 
	 * @return a future which completes with the handle to the new vm
	 */
	CompletableFuture<VirtualMachine> addVM(Connector cx, List<String> args);

	CompletableFuture<VirtualMachine> addVM(Connector cx, Map<String, Argument> args);

	/**
	 * Remove a vm
	 * 
	 * @param vm the vm to remove
	 * @return a future which completes then JDI has executed the command
	 */
	CompletableFuture<Void> removeVM(VirtualMachine vm);

	/**
	 * Execute an arbitrary CLI command, printing output to the CLI console
	 * 
	 * Note: to ensure a certain thread or inferior has focus for a console command, see
	 * {@link JdiThread#console(String)} and {@link JdiVM#console(String)}.
	 * 
	 * @param command the command to execute
	 * @return a future that completes when JDI has executed the command
	 */
	CompletableFuture<Void> console(String command);

	/**
	 * Execute an arbitrary CLI command, capturing its console output
	 * 
	 * The output will not be printed to the CLI console. To ensure a certain thread or inferior has
	 * focus for a console command, see {@link JdiThread#consoleCapture(String)} and
	 * {@link JdiVM#consoleCapture(String)}.
	 * 
	 * @param command the command to execute
	 * @return a future that completes with the captured output when JDI has executed the command
	 */
	CompletableFuture<String> consoleCapture(String command);

	/**
	 * List JDI's virtual machines
	 * 
	 * @return a future that completes with a map of inferior IDs to inferior handles
	 */
	CompletableFuture<Map<String, VirtualMachine>> listVMs();

	/**
	 * List the available processes on target
	 * 
	 * @return a future that completes with a list of PIDs
	 */
	@Deprecated(forRemoval = true)
	CompletableFuture<List<Pair<Integer, String>>> listAvailableProcesses();

	public VirtualMachineManager getVirtualMachineManager();

	JdiEventHandler getEventHandler(VirtualMachine vm);

}
