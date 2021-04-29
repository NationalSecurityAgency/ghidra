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
package ghidra.dbg.target;

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * A command interpreter, usually that of a native debugger
 */
@DebuggerTargetObjectIface("Interpreter")
public interface TargetInterpreter extends TargetObject {

	String PROMPT_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "prompt";

	/**
	 * Execute an interpreter command
	 * 
	 * <p>
	 * Usually, this means executing a command as if typed into the debugger's CLI. Thus, the
	 * meaning of the command will depend on the debugger. As such, this method is discouraged for
	 * scripts that intend to be debugger agnostic. On the other hand, this is often a very useful
	 * feature for a user interface.
	 * 
	 * @param cmd the command to issue to the CLI
	 * @return a future that completes when the command has completed execution
	 */
	public CompletableFuture<Void> execute(String cmd);

	/**
	 * Execute an interpreter command, capturing the output
	 * 
	 * <p>
	 * This works the same as {@link #execute(String)}, but instead of writing the output to the
	 * console, it is captured. This method is discouraged for scripts that intend to be debugger
	 * agnostic.
	 * 
	 * @param cmd the command to issue to the CLI
	 * @return a future that completes with the captured output
	 */
	public CompletableFuture<String> executeCapture(String cmd);

	/**
	 * Get the prompt for user input
	 * 
	 * <p>
	 * Generally, this should indicate to the user the command language and/or state of the
	 * interpreter. For some debuggers, this may change as the interpreter context changes. For
	 * example, the {@code dbgeng.dll} interpreter provides a prompt indicating the effective
	 * instruction set architecture for the current thread.
	 * 
	 * @return the current prompt
	 */
	@TargetAttributeType(name = PROMPT_ATTRIBUTE_NAME, required = true, hidden = true)
	public default String getPrompt() {
		return getTypedAttributeNowByName(PROMPT_ATTRIBUTE_NAME, String.class, ">");
	}
}
