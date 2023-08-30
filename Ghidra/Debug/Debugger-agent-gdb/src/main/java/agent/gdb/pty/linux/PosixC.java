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

import com.sun.jna.*;
import com.sun.jna.Structure.FieldOrder;

/**
 * Interface for POSIX functions in libc
 * 
 * <p>
 * The functions are not documented here. Instead see the POSIX manual pages.
 */
public interface PosixC extends Library {

	@FieldOrder({ "c_iflag", "c_oflag", "c_cflag", "c_lflag", "c_line", "c_cc", "c_ispeed",
		"c_ospeed" })
	class Termios extends Structure {
		public static final int TCSANOW = 0;

		public static final int ECHO = 0000010; // Octal

		public int c_iflag;
		public int c_oflag;
		public int c_cflag;
		public int c_lflag;

		public byte c_line;
		public byte[] c_cc = new byte[32];

		public int c_ispeed;
		public int c_ospeed;

		public static class ByReference extends Termios implements Structure.ByReference {
		}
	}

	/**
	 * The bare library without error handling
	 * 
	 * @see Util#BARE
	 */
	PosixC BARE = Native.load("c", PosixC.class);

	PosixC INSTANCE = new PosixC() {
		@Override
		public String strerror(int errnum) {
			return BARE.strerror(errnum);
		}

		@Override
		public int close(int fd) {
			return Err.checkLt0(BARE.close(fd));
		}

		@Override
		public int read(int fd, Pointer buf, int len) {
			return Err.checkLt0(BARE.read(fd, buf, len));
		}

		@Override
		public int write(int fd, Pointer buf, int i) {
			return Err.checkLt0(BARE.write(fd, buf, i));
		}

		@Override
		public int setsid() {
			return Err.checkLt0(BARE.setsid());
		}

		@Override
		public int open(String path, int mode, int flags) {
			return Err.checkLt0(BARE.open(path, mode, flags));
		}

		@Override
		public int dup2(int oldfd, int newfd) {
			return Err.checkLt0(BARE.dup2(oldfd, newfd));
		}

		@Override
		public int execv(String path, String[] argv) {
			return Err.checkLt0(BARE.execv(path, argv));
		}

		@Override
		public int tcgetattr(int fd, Termios.ByReference termios_p) {
			return Err.checkLt0(BARE.tcgetattr(fd, termios_p));
		}

		@Override
		public int tcsetattr(int fd, int optional_actions, Termios.ByReference termios_p) {
			return Err.checkLt0(BARE.tcsetattr(fd, optional_actions, termios_p));
		}
	};

	String strerror(int errnum);

	int close(int fd);

	int read(int fd, Pointer buf, int len);

	int write(int fd, Pointer buf, int i);

	int setsid();

	int open(String path, int mode, int flags);

	int dup2(int oldfd, int newfd);

	int execv(String path, String[] argv);

	int tcgetattr(int fd, Termios.ByReference termios_p);

	int tcsetattr(int fd, int optional_actions, Termios.ByReference termios_p);
}
