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

import java.nio.charset.Charset;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.lifecycle.Experimental;

/**
 * A user-facing console
 * 
 * <p>
 * This could be a CLI for the native debugger, or I/O for a target, or anything else the model
 * might like to expose in terminal-like fashion.
 * 
 * <p>
 * This is still an experimental concept and has not been implemented in any model. While it seems
 * like an abstract case of {@link TargetInterpreter}, their specifications don't seem to line up.
 * E.g., implementing the CLI as a {@link TargetConsole} requires the server to buffer and parse
 * line input; whereas, implementing the CLI as a {@link TargetInterpreter} requires the client to
 * parse line input.
 */
@Experimental
@DebuggerTargetObjectIface("Console")
public interface TargetConsole extends TargetObject {
	Charset CHARSET = Charset.forName("utf-8");

	/**
	 * For console output notifications, indicates whether it is normal or error output
	 */
	public static enum Channel {
		STDOUT, STDERR;
	}

	/**
	 * Write data to the console's input
	 * 
	 * @param data the data, often utf-8-encoded text
	 * @return a future which completes when the data is sent
	 */
	public CompletableFuture<Void> write(byte[] data);
}
