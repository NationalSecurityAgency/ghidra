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

import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;

public interface GdbConsoleOperations {
	/**
	 * Execute an arbitrary CLI command, printing output to the CLI console
	 * 
	 * <p>
	 * The command is executed in the context of this object. If more specific context is necessary,
	 * it will take from whatever happens to be selected, e.g., the current thread.
	 * 
	 * @param command the command to execute
	 * @param cwr specifies expected state change behavior
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> console(String command, CompletesWithRunning cwr);

	/**
	 * Equivalent to {@link #console(String, CompletesWithRunning)} with no behavior restriction
	 * 
	 * @param command the command to execute
	 * @return a future that completes when GDB has executed the command
	 */
	default CompletableFuture<Void> console(String command) {
		return console(command, CompletesWithRunning.CAN);
	}

	/**
	 * Execute an arbitrary CLI command, capturing its console output
	 * 
	 * <p>
	 * The output will not be printed to the CLI console. The command is executed in the context of
	 * this object. If more specific context is necessary, it will take from whatever happens to be
	 * selected, e.g., the current thread.
	 * 
	 * @param command the command to execute
	 * @param cwr specifies expected state change behavior
	 * @return a future that completes with the captured output when GDB has executed the command
	 */
	CompletableFuture<String> consoleCapture(String command, CompletesWithRunning cwr);

	/**
	 * Equivalent to {@link #consoleCapture(String, CompletesWithRunning)} with no behavior
	 * restriction
	 * 
	 * @param command the command to execute
	 * @return a future that completes with the captured output when GDB has executed the command
	 */
	default CompletableFuture<String> consoleCapture(String command) {
		return consoleCapture(command, CompletesWithRunning.CAN);
	}
}
