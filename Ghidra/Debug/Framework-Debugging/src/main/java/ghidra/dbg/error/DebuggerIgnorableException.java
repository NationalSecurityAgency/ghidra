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
package ghidra.dbg.error;

import ghidra.async.AsyncUtils;

/**
 * An exception which should not alert the user
 * 
 * <p>
 * At most, it can be logged, probably without a stack trace. These are sorts of soft warnings,
 * which might be issued when an exception is a normal occurrence. One example is when a model is
 * shutting down. It's common for requests in the queue to be rejected once the model beings
 * shutting down. Exceptions raised by those requests can likely be ignored. Please note, clients
 * will likely need to apply {@link AsyncUtils#unwrapThrowable(Throwable)} in order to determine
 * whether the exception is ignorable. Alternatively, use {@link #isIgnorable(Throwable)}.
 */
public class DebuggerIgnorableException extends DebuggerRuntimeException {
	public static boolean isIgnorable(Throwable ex) {
		Throwable u = AsyncUtils.unwrapThrowable(ex);
		return u instanceof DebuggerIgnorableException;
	}

	public DebuggerIgnorableException(String message, Throwable cause) {
		super(message, cause);
	}

	public DebuggerIgnorableException(String message) {
		super(message);
	}
}
