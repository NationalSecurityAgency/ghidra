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
package agent.gdb.ffi.linux;

import java.io.IOException;
import java.nio.ByteBuffer;

import ghidra.util.Msg;
import jnr.ffi.Pointer;
import jnr.ffi.byref.IntByReference;
import jnr.posix.POSIX;
import jnr.posix.POSIXFactory;

/**
 * A pseudo-terminal
 * 
 * A pseudo-terminal is essentially a two way pipe where one end acts as the master, and the other
 * acts as the slave. The process opening the pseudo-terminal is given a handle to both ends. The
 * slave end is generally given to a subprocess, possibly designating the pty as the controlling tty
 * of a new session. This scheme is how, for example, an SSH daemon starts a new login shell. The
 * shell is given the slave end, and the master end is presented to the SSH client.
 * 
 * This is more powerful than controlling a process via standard in and standard out. 1) Some
 * programs detect whether or not stdin/out/err refer to the controlling tty. For example, a program
 * should avoid prompting for passwords unless stdin is the controlling tty. Using a pty can provide
 * a controlling tty that is not necessarily controlled by a user. 2) Terminals have other
 * properties and can, e.g., send signals to the foreground process group (job) by sending special
 * characters. Normal characters are passed to the slave, but special characters may be interpreted
 * by the terminal's <em>line discipline</em>. A rather common case is to send Ctrl-C (character
 * 003). Using stdin, the subprocess simply reads 003. With a properly-configured pty and session,
 * the subprocess is interrupted (sent SIGINT) instead.
 * 
 * This class opens a pseudo-terminal and presents both ends as individual handles. The master end
 * simply provides an input and output stream. These are typical byte-oriented streams, except that
 * the data passes through the pty, subject to interpretation by the OS kernel. On Linux, this means
 * the pty will apply the configured line discipline. Consult the host OS documentation for special
 * character sequences.
 * 
 * The slave end also provides the input and output streams, but it is uncommon to use them from the
 * same process. More likely, subprocess is launched in a new session, configuring the slave as the
 * controlling terminal. Thus, the slave handle provides methods for obtaining the slave pty file
 * name and/or spawning a new session. Once spawned, the master end is used to control the session.
 * 
 * Example:
 * 
 * <pre>
 * Pty pty = Pty.openpty();
 * pty.getSlave().session("bash");
 * 
 * PrintWriter writer = new PrintWriter(pty.getMaster().getOutputStream());
 * writer.println("echo test");
 * BufferedReader reader =
 * 	new BufferedReader(new InputStreamReader(pty.getMaster().getInputStream()));
 * System.out.println(reader.readLine());
 * System.out.println(reader.readLine());
 * 
 * pty.close();
 * </pre>
 */
public class Pty implements AutoCloseable {
	private static final POSIX LIB_POSIX = POSIXFactory.getNativePOSIX();

	private final int amaster;
	private final int aslave;
	private final String name;
	private boolean closed = false;

	/**
	 * Open a new pseudo-terminal
	 * 
	 * Implementation note: On Linux, this invokes the native {@code openpty()} function. See the
	 * Linux manual for details.
	 * 
	 * @return new new Pty
	 * @throws IOException if openpty fails
	 */
	public static Pty openpty() throws IOException {
		// TODO: Support termp and winp?
		IntByReference m = new IntByReference();
		IntByReference s = new IntByReference();
		Pointer n = Pointer.wrap(jnr.ffi.Runtime.getSystemRuntime(), ByteBuffer.allocate(1024));
		if (Util.INSTANCE.openpty(m, s, n, null, null) < 0) {
			int errno = LIB_POSIX.errno();
			throw new IOException(errno + ": " + LIB_POSIX.strerror(errno));
		}
		return new Pty(m.intValue(), s.intValue(), n.getString(0));
	}

	Pty(int amaster, int aslave, String name) {
		Msg.debug(this, "New Pty: " + name + " at (" + amaster + "," + aslave + ")");
		this.amaster = amaster;
		this.aslave = aslave;
		this.name = name;
	}

	/**
	 * Get a handle to the master side of the pty
	 * 
	 * @return the master handle
	 */
	public PtyMaster getMaster() {
		return new PtyMaster(amaster);
	}

	/**
	 * Get a handle to the slave side of the pty
	 * 
	 * @return the slave handle
	 */
	public PtySlave getSlave() {
		return new PtySlave(aslave, name);
	}

	/**
	 * Closes both ends of the pty
	 * 
	 * This only closes this process's handles to the pty. For the master end, this should be the
	 * only process with a handle. The slave end may be opened by any number of other processes.
	 * More than likely, however, those processes will terminate once the master end is closed,
	 * since reads or writes on the slave will produce EOF or an error.
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public synchronized void close() throws IOException {
		if (closed) {
			return;
		}
		int result;
		result = LIB_POSIX.close(aslave);
		if (result < 0) {
			throw new IOException(LIB_POSIX.strerror(LIB_POSIX.errno()));
		}
		result = LIB_POSIX.close(amaster);
		if (result < 0) {
			throw new IOException(LIB_POSIX.strerror(LIB_POSIX.errno()));
		}
		closed = true;
	}
}
