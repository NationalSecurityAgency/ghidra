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
package ghidra.debug.api.tracermi;

import java.io.IOException;

/**
 * A terminal with some back-end element attached to it
 */
public interface TerminalSession extends AutoCloseable {
	@Override
	void close() throws IOException;

	/**
	 * Terminate the session without closing the terminal
	 */
	void terminate() throws IOException;

	/**
	 * Check whether the terminal session is terminated or still active
	 * 
	 * @return true for terminated, false for active
	 */
	boolean isTerminated();

	/**
	 * Provide a human-readable description of the session
	 * 
	 * @return the description
	 */
	String description();
}
