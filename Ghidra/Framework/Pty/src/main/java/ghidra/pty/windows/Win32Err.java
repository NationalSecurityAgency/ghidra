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
package ghidra.pty.windows;

import java.lang.foreign.*;
import java.lang.invoke.VarHandle;
import java.nio.charset.Charset;

import com.microsoft.win32.win32_h;

public interface Win32Err {
	Linker.Option OPT_CAPTURE_LASTERROR = Linker.Option.captureCallState("GetLastError");
	StructLayout LAYOUT = Linker.Option.captureStateLayout();
	VarHandle LASTERROR = LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));

	class LastErrorException extends RuntimeException {
		private final int lastError;

		public LastErrorException(int lastError, String message) {
			super("[%d] %s".formatted(lastError, message));
			this.lastError = lastError;
		}

		public int getLastError() {
			return lastError;
		}
	}

	static String formatMessage(int lastError) {
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment pBuf = arena.allocate(win32_h.LPWSTR);
			int lenWchars = win32_h.FormatMessageW(
				win32_h.FORMAT_MESSAGE_ALLOCATE_BUFFER() | win32_h.FORMAT_MESSAGE_ARGUMENT_ARRAY() |
					win32_h.FORMAT_MESSAGE_FROM_SYSTEM() | win32_h.FORMAT_MESSAGE_IGNORE_INSERTS(),
				// dwFlags
				MemorySegment.NULL, // lpSource
				lastError, // dwMessageId
				0, // dwLanguageId
				pBuf, // lpBuffer
				0, // nSize
				MemorySegment.NULL); // Arguments
			if (lenWchars == 0) {
				return "[FormatMessage failed]";
			}
			int lenBytes = lenWchars * 2;
			MemorySegment unmanaged = pBuf.get(win32_h.LPWSTR, 0);
			byte[] managed = new byte[lenBytes];
			MemorySegment.copy(unmanaged, ValueLayout.JAVA_BYTE, 0, managed, 0, lenBytes);
			win32_h.LocalFree(unmanaged);
			return new String(managed, Charset.forName("UTF-16LE"));
		}
	}

	static void checkFalse(int result, MemorySegment cs) {
		if (result == 0) {
			int lastError = (int) LASTERROR.get(cs, 0);
			throw new LastErrorException(lastError, formatMessage(lastError));
		}
	}

	static void checkHResult(int result, MemorySegment cs) {
		if (result != win32_h.S_OK()) {
			int lastError = (int) LASTERROR.get(cs, 0);
			throw new LastErrorException(lastError, formatMessage(lastError));
		}
	}

	static MemorySegment checkNull(MemorySegment result, MemorySegment cs) {
		if (result.address() == 0) {
			int lastError = (int) LASTERROR.get(cs, 0);
			throw new LastErrorException(lastError, formatMessage(lastError));
		}
		return result;
	}

	static int checkWaitFailed(int result, MemorySegment cs) {
		if (result == win32_h.WAIT_FAILED()) {
			int lastError = (int) LASTERROR.get(cs, 0);
			throw new LastErrorException(lastError, formatMessage(lastError));
		}
		return result;
	}
}
