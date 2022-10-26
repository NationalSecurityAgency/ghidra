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

/**
 * Interface for POSIX functions in libc
 * 
 * <p>
 * The functions are not documented here. Instead see the POSIX manual pages.
 */
public interface PosixC extends Library {
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
	};

	String strerror(int errnum);

	int close(int fd);

	int read(int fd, Pointer buf, int len);

	int write(int fd, Pointer buf, int i);

	int setsid();

	int open(String path, int mode, int flags);

	int dup2(int oldfd, int newfd);

	int execv(String path, String[] argv);
}
