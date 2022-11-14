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

public class LinuxPtySessionLeader {
	private static final PosixC LIB_POSIX = PosixC.INSTANCE;
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

	protected void run() throws Exception {
		/** This tells Linux to make this process the leader of a new session. */
		LIB_POSIX.setsid();

		/**
		 * Open the TTY. On Linux, the first TTY opened since becoming a session leader becomes the
		 * session's controlling TTY. Other platforms, e.g., BSD may require an explicit IOCTL.
		 */
		int bk = -1;
		try {
			int fd = LIB_POSIX.open(ptyPath, O_RDWR, 0);

			/** Copy stderr to a backup descriptor, in case something goes wrong. */
			int bkt = fd + 1;
			LIB_POSIX.dup2(2, bkt);
			bk = bkt;

			/**
			 * Copy the TTY fd over all standard streams. This effectively redirects the leader's
			 * standard streams to the TTY.
			 */
			LIB_POSIX.dup2(fd, 0);
			LIB_POSIX.dup2(fd, 1);
			LIB_POSIX.dup2(fd, 2);

			/**
			 * At this point, we are the session leader and the named TTY is the controlling PTY.
			 * Now, exec the specified image with arguments as the session leader. Recall, this
			 * replaces the image of this process.
			 */
			LIB_POSIX.execv(subArgs.get(0), subArgs.toArray(new String[0]));
		}
		catch (Throwable t) {
			if (bk != -1) {
				try {
					int bkt = bk;
					LIB_POSIX.dup2(bkt, 2);
				}
				catch (Throwable t2) {
					// Catastrophic
					System.exit(-1);
				}
			}
			System.err.println("Could not execute " + subArgs.get(0) + ": " + t.getMessage());
			System.exit(127);
		}
	}
}
