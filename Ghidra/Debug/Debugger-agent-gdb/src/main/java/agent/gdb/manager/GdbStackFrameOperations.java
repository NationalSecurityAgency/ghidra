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

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public interface GdbStackFrameOperations {
	/**
	 * Evaluate an expression
	 * 
	 * This evaluates an expression in the same way that the CLI commands {@code print},
	 * {@code output}, and {@code call} would.
	 * 
	 * @param expression the expression to evaluate
	 * @return a future that completes with the string representation of the value
	 */
	CompletableFuture<String> evaluate(String expression);

	/**
	 * Read the values of a given set of registers
	 * 
	 * @param regs the set of registers
	 * @return a future that completes with a map of register descriptors to value
	 */
	CompletableFuture<Map<GdbRegister, BigInteger>> readRegisters(Set<GdbRegister> regs);

	/**
	 * Write the values of a given set of registers
	 * 
	 * @param regVals a map of register descriptors to value
	 * @return a future that completes when the registers have been written
	 */
	CompletableFuture<Void> writeRegisters(Map<GdbRegister, BigInteger> regVals);

	/**
	 * Execute an arbitrary CLI command, printing output to the CLI console
	 * 
	 * @param command the command to execute
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> console(String command);

	/**
	 * Execute an arbitrary CLI command, capturing its console output
	 * 
	 * The output will not be printed to the CLI console.
	 * 
	 * @param command the command to execute
	 * @return a future that completes with the captured output when GDB has executed the command
	 */
	CompletableFuture<String> consoleCapture(String command);

}
