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
import java.lang.invoke.VarHandle;

import org.unix.string_h;

public interface UnixErr {
	Linker.Option OPT_CAPTURE_ERRNO = Linker.Option.captureCallState("errno");
	StructLayout LAYOUT = Linker.Option.captureStateLayout();
	VarHandle ERRNO = LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("errno"));

	class ErrnoException extends RuntimeException {
		private final int errno;

		public ErrnoException(int errno, String message) {
			super("[%d] %s".formatted(errno, message));
			this.errno = errno;
		}

		public int getErrno() {
			return errno;
		}
	}

	static String strerror(int errno) {
		MemorySegment errstr = string_h.strerror(errno);
		if (errstr.address() != 0) {
			return errstr.getString(0);
		}
		return "Unknown";
	}

	static int checkLt0(int result, MemorySegment cs) {
		if (result < 0) {
			int errno = (int) ERRNO.get(cs, 0);
			throw new ErrnoException(errno, strerror(errno));
		}
		return result;
	}

	static long checkLt0(long result, MemorySegment cs) {
		if (result < 0) {
			int errno = (int) ERRNO.get(cs, 0);
			throw new ErrnoException(errno, strerror(errno));
		}
		return result;
	}
}
