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

/**
 * A pseudo-terminal
 * 
 * <p>
 * A pseudo-terminal is essentially a two way pipe where one end acts as the parent, and the other
 * acts as the child. The process opening the pseudo-terminal is given a handle to both ends. The
 * child end is generally given to a subprocess, possibly designating the pty as the controlling tty
 * of a new session. This scheme is how, for example, an SSH daemon starts a new login shell. The
 * shell is given the child end, and the parent end is presented to the SSH client.
 * 
 * <p>
 * This is more powerful than controlling a process via standard in and standard out. 1) Some
 * programs detect whether or not stdin/out/err refer to the controlling tty. For example, a program
 * should avoid prompting for passwords unless stdin is the controlling tty. Using a pty can provide
 * a controlling tty that is not necessarily controlled by a user. 2) Terminals have other
 * properties and can, e.g., send signals to the foreground process group (job) by sending special
 * characters. Normal characters are passed to the child, but special characters may be interpreted
 * by the terminal's <em>line discipline</em>. A rather common case is to send Ctrl-C (character
 * 003). Using stdin, the subprocess simply reads 003. With a properly-configured pty and session,
 * the subprocess is interrupted (sent SIGINT) instead.
 * 
 * <p>
 * This class opens a pseudo-terminal and presents both ends as individual handles. The parent end
 * simply provides an input and output stream. These are typical byte-oriented streams, except that
 * the data passes through the pty, subject to interpretation by the OS kernel. On Linux, this means
 * the pty will apply the configured line discipline. Consult the host OS documentation for special
 * character sequences.
 * 
 * <p>
 * The child end also provides the input and output streams, but it is uncommon to use them from the
 * same process. More likely, subprocess is launched in a new session, configuring the child as the
 * controlling terminal. Thus, the child handle provides methods for obtaining the child pty file
 * name and/or spawning a new session. Once spawned, the parent end is used to control the session.
 * 
 * <p>
 * Example:
 * 
 * <pre>
 * Pty pty = factory.openpty();
 * pty.getChild().session("bash");
 * 
 * PrintWriter writer = new PrintWriter(pty.getParent().getOutputStream());
 * writer.println("echo test");
 * BufferedReader reader =
 * 	new BufferedReader(new InputStreamReader(pty.getParent().getInputStream()));
 * System.out.println(reader.readLine());
 * System.out.println(reader.readLine());
 * 
 * pty.close();
 * </pre>
 */
public interface Pty extends AutoCloseable {

	/**
	 * Get a handle to the parent side of the pty
	 * 
	 * @return the parent handle
	 */
	PtyParent getParent();

	/**
	 * Get a handle to the child side of the pty
	 * 
	 * @return the child handle
	 */
	PtyChild getChild();

	/**
	 * Closes both ends of the pty
	 * 
	 * <p>
	 * This only closes this process's handles to the pty. For the parent end, this should be the
	 * only process with a handle. The child end may be opened by any number of other processes.
	 * More than likely, however, those processes will terminate once the parent end is closed,
	 * since reads or writes on the child will produce EOF or an error.
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	void close() throws IOException;
}
