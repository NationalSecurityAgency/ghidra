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
package agent.dbgeng.manager;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.jna.dbgeng.WinNTExtra.Machine;
import agent.dbgeng.manager.DbgManager.ExecSuffix;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInsertions;
import agent.dbgeng.manager.impl.DbgRegisterSet;

public interface DbgThread
		extends DbgBreakpointInsertions, DbgMemoryOperations, DbgStackFrameOperations {

	/**
	 * Get the dbgeng-assigned thread number
	 * 
	 * This is not the OS-assigned TID.
	 * 
	 * @return the number
	 */
	DebugThreadId getId();

	Long getTid();

	/**
	 * Get the state of the thread, {@link DbgState#RUNNING} or {@link DbgState#STOPPED}.
	 * 
	 * @return the state
	 */
	DbgState getState();

	/**
	 * Set the state of this thread
	 * 
	 * @param state the new state
	 * @param cause the cause for the change
	 * @param reason the reason (usually a stop reason) for the change
	 * @return true if the state actually changed
	 */
	boolean setState(DbgState state, DbgCause cause, DbgReason reason);

	/**
	 * Make this thread the current thread
	 * 
	 * @return a future that completes when the thread is the current thread
	 */
	CompletableFuture<Void> setActive();

	/**
	 * Get the process to which this thread belongs
	 * 
	 * @return the process
	 */
	DbgProcess getProcess();

	/**
	 * List the frames of this thread's stack
	 * 
	 * @return the list of stack frames
	 */
	CompletableFuture<List<DbgStackFrame>> listStackFrames();

	/**
	 * List the registers available to this thread
	 * 
	 * @return a future that completes with a map of register names to descriptors
	 */
	CompletableFuture<DbgRegisterSet> listRegisters();

	/**
	 * Continue execution
	 * 
	 * This is equivalent to the CLI command: {@code continue}. Depending on GDB's execution mode,
	 * this may allow other threads to execute, too.
	 * 
	 * @return a future that completes once the thread is running
	 */
	CompletableFuture<Void> cont();

	/**
	 * Step the thread
	 * 
	 * Note that the command can complete before the thread has finished stepping. The command
	 * completes as soon as the thread is running. A separate stop event is emitted when the step is
	 * completed.
	 * 
	 * @param suffix specifies how far to step, or on what conditions stepping ends.
	 * 
	 * @return a future that completes once the thread is running
	 */
	CompletableFuture<Void> step(ExecSuffix suffix);

	/**
	 * Step the thread
	 * 
	 * Note that the command can complete before the thread has finished stepping. The command
	 * completes as soon as the thread is running. A separate stop event is emitted when the step is
	 * completed.
	 * 
	 * @param args specifies how far to step, or on what conditions stepping ends.
	 * 
	 * @return a future that completes once the thread is running
	 */
	CompletableFuture<Void> step(Map<String, ?> args);

	/**
	 * Detach from the entire process
	 * 
	 * This is equivalent to the CLI command {@code detach}. It will detach the entire process, not
	 * just this thread.
	 * 
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> kill();

	/**
	 * Kill the entire process
	 * 
	 * This is equivalent to the CLI command {@code kill}. It will kill the entire process, not just
	 * this thread.
	 * 
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> detach();

	/**
	 * Get the effective architecture for the executing thread
	 * 
	 * @return a future that completes when GDB has executed the command
	 */
	Machine getExecutingProcessorType();

}
