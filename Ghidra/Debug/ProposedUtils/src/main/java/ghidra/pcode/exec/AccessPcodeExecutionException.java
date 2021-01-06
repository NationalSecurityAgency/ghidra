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
package ghidra.pcode.exec;

/**
 * There was an issue accessing the executor's state, i.e., memory or register values
 */
public class AccessPcodeExecutionException extends PcodeExecutionException {
	public AccessPcodeExecutionException(String message, PcodeFrame frame, Throwable cause) {
		super(message, frame, cause);
	}

	public AccessPcodeExecutionException(String message, Exception cause) {
		super(message, cause);
	}

	public AccessPcodeExecutionException(String message) {
		super(message);
	}
}
