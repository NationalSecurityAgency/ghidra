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
package ghidra.pty;

import java.io.IOException;
import java.util.*;

/**
 * The child (UNIX "slave") end of a pseudo-terminal
 */
public interface PtyChild extends PtyEndpoint {

	/**
	 * A terminal mode flag
	 */
	interface TermMode {
	}

	/**
	 * Mode flag for local echo
	 */
	enum Echo implements TermMode {
		/**
		 * Input is echoed to output by the terminal itself.
		 */
		ON,
		/**
		 * No local echo.
		 */
		OFF;
	}

	/**
	 * Spawn a subprocess in a new session whose controlling tty is this pseudo-terminal
	 * 
	 * <p>
	 * This method or {@link #nullSession(Collection)} can only be invoked once per pty.
	 * 
	 * @param args the image path and arguments
	 * @param env the environment
	 * @param mode the terminal mode. If a mode is not implemented, it may be silently ignored.
	 * @return a handle to the subprocess
	 * @throws IOException if the session could not be started
	 */
	PtySession session(String[] args, Map<String, String> env, Collection<TermMode> mode)
			throws IOException;

	default PtySession session(String[] args, Map<String, String> env, TermMode... mode)
			throws IOException {
		return session(args, env, List.of(mode));
	}

	/**
	 * Start a session without a real leader, instead obtaining the pty's name
	 * 
	 * <p>
	 * This method or {@link #session(String[], Map, Collection)} can only be invoked once per pty.
	 * It must be called before anyone reads the parent's output stream, since obtaining the
	 * filename may be implemented by the parent sending commands to its child.
	 * 
	 * <p>
	 * If the child end of the pty is on a remote system, this should be the file (or other
	 * resource) name as it would be accessed on that remote system.
	 * 
	 * @param mode the terminal mode. If a mode is not implemented, it may be silently ignored.
	 * @return the file name
	 * @throws IOException if the session could not be started or the pty name could not be
	 *             determined
	 */
	String nullSession(Collection<TermMode> mode) throws IOException;

	default String nullSession(TermMode... mode) throws IOException {
		return nullSession(List.of(mode));
	}
}
