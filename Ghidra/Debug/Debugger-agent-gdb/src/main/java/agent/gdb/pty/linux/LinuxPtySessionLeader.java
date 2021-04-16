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
package agent.gdb.pty.linux;

import java.util.List;
import java.util.concurrent.Callable;

import jnr.posix.POSIX;
import jnr.posix.POSIXFactory;

public class LinuxPtySessionLeader {
	private static final POSIX LIB_POSIX = POSIXFactory.getNativePOSIX();
	private static final int O_RDWR = 2; // TODO: Find this in libs

	public static void main(String[] args) throws Exception {
		LinuxPtySessionLeader leader = new LinuxPtySessionLeader();
		leader.parseArgs(args);
		leader.run();
	}

	protected String ptyPath;
	protected List<String> subArgs;

	protected void parseArgs(String[] args) {
		ptyPath = args[0];
		subArgs = List.of(args).subList(1, args.length);
	}

	protected <T> T checkErr(Callable<T> r) throws Exception {
		LIB_POSIX.errno(0);
		T result = r.call();
		int errno = LIB_POSIX.errno();
		if (errno != 0) {
			throw new RuntimeException("errno=" + errno + ": " + LIB_POSIX.strerror(errno));
		}
		return result;
	}

	protected void run() throws Exception {
		/** This tells Linux to make this process the leader of a new session. */
		checkErr(() -> LIB_POSIX.setsid());

		/**
		 * Open the TTY. On Linux, the first TTY opened since becoming a session leader becomes the
		 * session's controlling TTY. Other platforms, e.g., BSD may require an explicit IOCTL.
		 */
		int fd = checkErr(() -> LIB_POSIX.open(ptyPath, O_RDWR, 0));

		/** Copy stderr to a backup descriptor, in case something goes wrong. */
		int bk = fd + 1;
		checkErr(() -> LIB_POSIX.dup2(2, bk));

		/**
		 * Copy the TTY fd over all standard streams. This effectively redirects the leader's
		 * standard streams to the TTY.
		 */
		checkErr(() -> LIB_POSIX.dup2(fd, 0));
		checkErr(() -> LIB_POSIX.dup2(fd, 1));
		checkErr(() -> LIB_POSIX.dup2(fd, 2));

		/**
		 * At this point, we are the session leader and the named TTY is the controlling PTY. Now,
		 * exec the specified image with arguments as the session leader. Recall, this replaces the
		 * image of this process.
		 */
		try {
			checkErr(() -> LIB_POSIX.execv(subArgs.get(0), subArgs.toArray(new String[0])));
		}
		catch (Throwable t) {
			try {
				checkErr(() -> LIB_POSIX.dup2(bk, 2));
			}
			catch (Throwable t2) {
				// Catastrophic
				System.exit(-1);
			}
			throw t;
		}
	}
}
