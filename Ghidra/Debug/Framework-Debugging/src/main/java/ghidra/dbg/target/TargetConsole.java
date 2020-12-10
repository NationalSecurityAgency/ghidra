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

@DebuggerTargetObjectIface("Console")
public interface TargetConsole<T extends TargetConsole<T>> extends TypedTargetObject<T> {
	Charset CHARSET = Charset.forName("utf-8");

	enum Private {
		;
		private abstract class Cls implements TargetConsole<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetConsole.class;

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

	public interface TargetConsoleListener extends TargetObjectListener {
		/**
		 * The console has produced output
		 * 
		 * @param console the console producing the output
		 * @param channel identifies the "output stream", stdout or stderr
		 * @param data the output data
		 */
		default void consoleOutput(TargetObject console, Channel channel, byte[] data) {
		}
	}

	public interface TargetTextConsoleListener extends TargetConsoleListener {
		/**
		 * The console has produced output
		 * 
		 * @param console the console producing the output
		 * @param channel identifies the "output stream", stdout or stderr
		 * @param text the output text
		 */
		default void consoleOutput(TargetObject console, Channel channel, String text) {
		}

		@Override
		default void consoleOutput(TargetObject console, Channel channel, byte[] data) {
			consoleOutput(console, channel, new String(data, CHARSET));
		}
	}
}
