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

import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.cmd.AbstractDbgCommand;
import agent.dbgeng.manager.cmd.DbgPendingCommand;

/**
 * The interface for Dbg command implementations
 *
 * Commands are executed by Dbg in serial. In order to distinguish the likely cause of events, the
 * manager will wait to issue each command until it has seen a prompt. Thus, commands are queued up,
 * and the manager uses the {@link CompletableFuture} pattern to "return" results after execution
 * completes. Once issued, a command is presumed to be executing until another prompt is received.
 * This generally immediately follows the command result, i.e., the "^..." result line in Dbg/MI.
 * The command implementation is responsible for handling the command result. Implementors ought to
 * use {@link AbstractDbgCommand} to ensure consistent processing.
 * 
 * To begin executing the command, the manager invokes the command, using {@link #invoke()}. Any
 * event that occurs during command execution is given to
 * {@link #handle(DbgEvent, DbgPendingCommand)}. The implementor then has the option to "claim" or
 * "steal" the event. When claimed, any subsequent event processor or listener is provided this
 * command as the event's cause. When stolen, no subsequent event processors are called. The
 * implementation ought to keep a list of claimed and stolen events. Once Dbg has finished executing
 * the command, the manager calls {@link #complete(DbgPendingCommand)}, allowing the implementation
 * to process its claimed and stolen events and return the result of the command.
 *
 * @param <T> the type of object "returned" by the command
 */
public interface DbgCommand<T> {

	/**
	 * Check if this command can be executed given Dbg's current state
	 * 
	 * @param state Dbg's state
	 * @return true if it can be executed, false otherwise
	 */
	public boolean validInState(DbgState state);

	/**
	 * Invoke the command
	 */
	public void invoke();

	/**
	 * Handle an event that ocurred during the execution of this command
	 * 
	 * @param evt the event
	 * @param pending a copy of the executing command instance
	 * @return true if the command is now ready to be completed
	 */
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending);

	/**
	 * Called when the manager believes this command is finished executing
	 * 
	 * This is presumed when the manager receives the prompt after issuing the encoded command
	 * 
	 * @param pending a copy of the now-finished-executing command instance
	 * @return the object "returned" by the command
	 */
	public T complete(DbgPendingCommand<?> pending);

}
