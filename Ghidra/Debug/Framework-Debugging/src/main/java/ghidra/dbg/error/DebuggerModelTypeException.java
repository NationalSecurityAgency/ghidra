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

import java.util.List;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

/**
 * 
 * @implNote I am not re-using {@link ClassCastException} here, as I don't want any of those thrown
 *           internally to be passed to the client.
 */
public class DebuggerModelTypeException extends DebuggerRuntimeException {
	public static DebuggerModelTypeException typeRequired(Object got, List<String> path,
			Class<?> expected) {
		return new DebuggerModelTypeException("Path " + PathUtils.toString(path) +
			" does not refer to a " + expected.getSimpleName() + ". Got " + got + " (of " +
			got.getClass().getSimpleName() + ")");
	}

	public static DebuggerModelTypeException linkForbidden(TargetObject got, List<String> path) {
		return new DebuggerModelTypeException("Path " + PathUtils.toString(path) +
			" is a link to " + PathUtils.toString(got.getPath()) +
			", but following links was forbidden");
	}

	public DebuggerModelTypeException(String message) {
		super(message);
	}

	public DebuggerModelTypeException(String message, Throwable cause) {
		super(message, cause);
	}
}
