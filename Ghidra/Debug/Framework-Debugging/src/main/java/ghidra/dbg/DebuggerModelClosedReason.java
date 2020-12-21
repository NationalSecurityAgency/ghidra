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
package ghidra.dbg;

/**
 * A reason given for a closed connection
 */
public interface DebuggerModelClosedReason {
	DebuggerModelClosedReason NORMAL = DebuggerNormalModelClosedReason.NORMAL;

	static DebuggerModelClosedReason normal() {
		return NORMAL;
	}

	static DebuggerModelClosedReason abnormal(Throwable exc) {
		return new DebuggerAbnormalModelClosedReason(exc);
	}

	/**
	 * Check for exceptional cause for the closed model
	 * 
	 * <p>
	 * Usually, if the model is closed unexpectedly, there is an exception to document the cause. If
	 * available, the implementation should provide this exception.
	 * 
	 * @return true if an exception is recorded
	 */
	boolean hasException();

	/**
	 * Check if the model was closed by the client
	 * 
	 * <p>
	 * In this case, the closed model is completely ordinary. While the model is still no longer
	 * valid, there is no cause to alert the user.
	 * 
	 * @return true if the model was closed by the client
	 */
	boolean isClientInitiated();

	/**
	 * Get the recorded exception, if available
	 * 
	 * @return the exception or null
	 */
	Throwable getException();
}
