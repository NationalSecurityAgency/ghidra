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
package ghidra.pty.unix;

import java.lang.foreign.*;
import java.util.List;

import org.unix.*;

public abstract class UnixPtySessionLeader {

	protected String ptyPath;
	protected List<String> subArgs;

	protected abstract Ioctls ioctls();

	protected void parseArgs(String[] args) {
		ptyPath = args[0];
		subArgs = List.of(args).subList(1, args.length);
	}

	protected void run() throws Exception {
		/**
		 * Open the TTY. On Linux, the first TTY opened since becoming a session leader becomes the
		 * session's controlling TTY. Other platforms, e.g., BSD may require an explicit IOCTL.
		 */
		int bk = -1;
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(UnixErr.LAYOUT);

			int fd = UnixErr.checkLt0(fcntl_h.open.makeInvoker(fcntl_h.mode_t)
					.apply(cs, arena.allocateFrom(ptyPath), fcntl_h.O_RDWR(), 0),
				cs);

			/** Copy stderr to a backup descriptor, in case something goes wrong. */
			bk = UnixErr.checkLt0(unistd_h.dup(cs, 2), cs);

			/**
			 * Copy the TTY fd over all standard streams. This effectively redirects the leader's
			 * standard streams to the TTY.
			 */
			UnixErr.checkLt0(unistd_h.close(cs, 0), cs);
			UnixErr.checkLt0(unistd_h.close(cs, 1), cs);
			UnixErr.checkLt0(unistd_h.close(cs, 2), cs);
			UnixErr.checkLt0(unistd_h.dup2(cs, fd, 0), cs);
			UnixErr.checkLt0(unistd_h.dup2(cs, fd, 1), cs);
			UnixErr.checkLt0(unistd_h.dup2(cs, fd, 2), cs);
			UnixErr.checkLt0(unistd_h.close(cs, fd), cs);

			/** This tells Linux to make this process the leader of a new session. */
			// returns sid/pid, but I don't care to keep it
			UnixErr.checkLt0(unistd_h.setsid(cs), cs);
			/** arg=0 declines to "steal" the terminal */
			UnixErr.checkLt0(ioctl_h.ioctl.makeInvoker(ioctl_h.C_INT)
					.apply(cs, 0, ioctls().TIOCSCTTY(), 0),
				cs);

			/**
			 * At this point, we are the session leader and the named TTY is the controlling PTY.
			 * Now, exec the specified image with arguments as the session leader. Recall, this
			 * replaces the image of this process.
			 */
			// One extra element to be the null arg terminator
			MemorySegment argsArr = arena.allocate(AddressLayout.ADDRESS, subArgs.size() + 1);
			for (int i = 0; i < subArgs.size(); i++) {
				argsArr.setAtIndex(AddressLayout.ADDRESS, i, arena.allocateFrom(subArgs.get(i)));
			}
			UnixErr.checkLt0(unistd_h.execv(cs,
				arena.allocateFrom(subArgs.get(0)),
				argsArr), cs);
		}
		catch (Throwable t) {
			// Print to both redirected and to inherited stderr
			System.err.println("Could not execute " + subArgs.get(0) + ": " + t.getMessage());
			t.printStackTrace();
			if (bk != -1) {
				try (Arena arena = Arena.ofConfined()) {
					MemorySegment cs = arena.allocate(UnixErr.LAYOUT);
					UnixErr.checkLt0(unistd_h.dup2(cs, bk, 2), cs);
				}
				catch (Throwable t2) {
					// Catastrophic
					System.exit(-1);
				}
			}
			System.err.println("Could not execute " + subArgs.get(0) + ": " + t.getMessage());
			t.printStackTrace();
			System.exit(127);
		}
	}
}
