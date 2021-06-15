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

/**
 * A model method was given an illegal argument.
 * 
 * If the argument is an object, but of the wrong type, please use
 * {@link DebuggerModelTypeException} instead. If the argument is a path which doesn't exist
 * in the model, use {@link DebuggerModelNoSuchPathException} instead.
 * 
 * @implNote I am not re-using {@link IllegalArgumentException} here, as I don't want any of those
 *           thrown internally to be passed to the client.
 */
public class DebuggerIllegalArgumentException extends DebuggerRuntimeException {
	public DebuggerIllegalArgumentException(String message) {
		super(message);
	}

	public DebuggerIllegalArgumentException(String message, Throwable cause) {
		super(message, cause);
	}
}
