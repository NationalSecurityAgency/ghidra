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
package agent.gdb.pty;

import java.io.IOException;
import java.util.Map;

/**
 * The child (UNIX "slave") end of a pseudo-terminal
 */
public interface PtyChild extends PtyEndpoint {

	/**
	 * Spawn a subprocess in a new session whose controlling tty is this pseudo-terminal
	 * 
	 * <p>
	 * This method or {@link #nullSession()} can only be invoked once per pty.
	 * 
	 * @param args the image path and arguments
	 * @param env the environment
	 * @return a handle to the subprocess
	 * @throws IOException if the session could not be started
	 */
	PtySession session(String[] args, Map<String, String> env) throws IOException;

	/**
	 * Start a session without a real leader, instead obtaining the pty's name
	 * 
	 * <p>
	 * This method or {@link #session(String[], Map)} can only be invoked once per pty. It must be
	 * called before anyone reads the parent's output stream, since obtaining the filename may be
	 * implemented by the parent sending commands to its child.
	 * 
	 * <p>
	 * If the child end of the pty is on a remote system, this should be the file (or other
	 * resource) name as it would be accessed on that remote system.
	 * 
	 * @return the file name
	 * @throws IOException if the session could not be started or the pty name could not be
	 *             determined
	 */
	String nullSession() throws IOException;
}
