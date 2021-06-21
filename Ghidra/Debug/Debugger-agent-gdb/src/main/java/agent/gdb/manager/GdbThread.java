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
package agent.gdb.manager;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbManager.StepCmd;
import agent.gdb.manager.breakpoint.GdbBreakpointInsertions;
import agent.gdb.manager.impl.GdbThreadInfo;

/**
 * A handle to a thread controlled by GDB
 * 
 * <p>
 * Each thread is numbered by GDB. Methods that return a {@link CompletableFuture} send a command to
 * GDB via its GDB/MI interpreter. Where applicable, the {@code --thread} parameter is provided to
 * GDB to ensure commands are executed on this thread. The returned future completes when GDB has
 * finished executing the command.
 */
public interface GdbThread
		extends GdbBreakpointInsertions, GdbMemoryOperations, GdbStackFrameOperations {

	/**
	 * Get the inferior to which this thread belongs
	 * 
	 * @return the inferior
	 */
	GdbInferior getInferior();

	/**
	 * Get the GDB-assigned thread number
	 * 
	 * <p>
	 * This is not the OS-assigned TID.
	 * 
	 * @return the number
	 */
	int getId();

	/**
	 * Get the GDB thread information
	 * 
	 * @return info
	 */
	CompletableFuture<GdbThreadInfo> getInfo();

	/**
	 * Get the state of the thread, {@link GdbState#RUNNING} or {@link GdbState#STOPPED}.
	 * 
	 * @return the state
	 */
	GdbState getState();

	/**
	 * Make this thread the current thread
	 * 
	 * @param internal true to prevent announcement of the change
	 * @return a future that completes when the thread is the current thread
	 */
	CompletableFuture<Void> setActive(boolean internal);

	/**
	 * Set the value of an internal GDB variable
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code set [VAR_NAME]=[VAL]}.
	 * 
	 * @param varName the name of the GDB variable
	 * @param val the value to assign
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> setVar(String varName, String val);

	/**
	 * List the registers available to this thread
	 * 
	 * @return a future that completes with a map of register names to descriptors
	 */
	CompletableFuture<GdbRegisterSet> listRegisters();

	/**
	 * List the frames of this thread's stack
	 * 
	 * @return
	 */
	CompletableFuture<List<GdbStackFrame>> listStackFrames();

	/**
	 * Continue execution
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code continue}. Depending on GDB's execution mode,
	 * this may allow other threads to execute, too.
	 * 
	 * @return a future that completes once the thread is running
	 */
	CompletableFuture<Void> cont();

	/**
	 * Step the thread
	 * 
	 * <p>
	 * Note that the command can complete before the thread has finished stepping. The command
	 * completes as soon as the thread is running. A separate stop event is emitted when the step is
	 * completed.
	 * 
	 * @param suffix specifies how far to step, or on what conditions stepping ends.
	 * @return a future that completes once the thread is running
	 */
	CompletableFuture<Void> step(StepCmd suffix);

	/**
	 * Detach from the entire process
	 * 
	 * <p>
	 * This is equivalent to the CLI command {@code detach}. It will detach the entire process, not
	 * just this thread.
	 * 
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> kill();

	/**
	 * Kill the entire process
	 * 
	 * <p>
	 * This is equivalent to the CLI command {@code kill}. It will kill the entire process, not just
	 * this thread.
	 * 
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> detach();

}
