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
package agent.gdb.manager.impl;

import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbState;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;
import agent.gdb.manager.impl.cmd.AbstractGdbCommand;
import agent.gdb.manager.impl.cmd.AbstractGdbCommandWithThreadId;

/**
 * The interface for GDB command implementations
 *
 * <p>
 * Commands are executed by GDB in serial. In order to distinguish the likely cause of events, the
 * manager will wait to issue each command until it has seen a prompt. Thus, commands are queued up,
 * and the manager uses the {@link CompletableFuture} pattern to "return" results after execution
 * completes. Once issued, a command is presumed to be executing until another prompt is received.
 * This generally immediately follows the command result, i.e., the "^..." result line in GDB/MI.
 * The command implementation is responsible for handling the command result. Implementors ought to
 * use {@link AbstractGdbCommand} or {@link AbstractGdbCommandWithThreadId} to ensure consistent
 * processing.
 * 
 * <p>
 * Before executing the command, the manager calls {@link #preCheck(GdbPendingCommand)}, giving the
 * implementation an opportunity to cancel the command or complete it early. If the command is
 * completed after the pre-check, the manager will not encode it, and instead proceed to the next
 * command. This is useful for eliminating unneeded "focus" commands. To begin executing the
 * command, the manager encodes the command, using {@link #encode()}. Any event that occurs during
 * command execution is given to {@link #handle(GdbEvent, GdbPendingCommand)}. The implementor then
 * has the option to "claim" or "steal" the event. When claimed, any subsequent event processor or
 * listener is provided this command as the event's cause. When stolen, no subsequent event
 * processors are called. The implementation ought to keep a list of claimed and stolen events. Once
 * GDB has finished executing the command, the manager calls {@link #complete(GdbPendingCommand)},
 * allowing the implementation to process its claimed and stolen events and return the result of the
 * command.
 *
 * @param <T> the type of object "returned" by the command
 */
public interface GdbCommand<T> {

	/**
	 * Check if this command can be executed given GDB's current state
	 * 
	 * @param state GDB's state
	 * @return true if it can be executed, false otherwise
	 */
	public boolean validInState(GdbState state);

	/**
	 * Perform any pre-execution screening for this command
	 * 
	 * <p>
	 * Complete {@code} pending with a result to short-circuit the execution of this command.
	 * 
	 * @param pending the pend@Override ing command result
	 */
	void preCheck(GdbPendingCommand<? super T> pending);

	/**
	 * Encode the command in GDB/MI
	 * 
	 * @return the encoded command
	 */
	public String encode();

	/**
	 * If executing this command changes the current thread, return that thread's ID
	 * 
	 * @return the new current thread ID
	 */
	public Integer impliesCurrentThreadId();

	/**
	 * If executing this command change the current frame, return that frame's ID
	 * 
	 * @return the new current frame ID
	 */
	public Integer impliesCurrentFrameId();

	/**
	 * Check if focus announcements from this command should be suppressed
	 * 
	 * @return true to suppress announcements
	 */
	public boolean isFocusInternallyDriven();

	/**
	 * Handle an event that occurred during the execution of this command
	 * 
	 * @param evt the event
	 * @param pending a copy of the executing command instance
	 * @return true if the command is now ready to be completed
	 */
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending);

	/**
	 * Called when the manager believes this command is finished executing
	 * 
	 * <p>
	 * This is presumed when the manager receives the prompt after issuing the encoded command
	 * 
	 * @param pending a copy of the now-finished-executing command instance
	 * @return the object "returned" by the command
	 */
	public T complete(GdbPendingCommand<?> pending);

	/**
	 * Get the interpreter for which this command is encoded
	 * 
	 * @return the interpreter
	 */
	public Interpreter getInterpreter();
}
