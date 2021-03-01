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

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

/**
 * An exception that may be thrown if an ancestor of an object is
 * {@link TargetAccessibility#INACCESSIBLE} at the time a method is invoked on that object.
 * 
 * <p>
 * In general, this exception should be considered a temporary condition, meaning the client should
 * just try again later. If a UI is involved, the error, if displayed at all, should be displayed in
 * the least obtrusive manner possible.
 */
public class DebuggerModelAccessException extends DebuggerRuntimeException {

	public DebuggerModelAccessException(String message, Throwable cause) {
		super(message, cause);
	}

	public DebuggerModelAccessException(String message) {
		super(message);
	}

	public DebuggerModelAccessException(TargetObject object) {
		super("Model path " + PathUtils.toString(object.getPath()) + " is not accessible");
	}
}
