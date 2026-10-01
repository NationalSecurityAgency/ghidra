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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import com.microsoft.win32.win32_h;

public class Pipe {
	public static Pipe createPipe() {
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			HandlePtr pRead = new HandlePtr(arena);
			HandlePtr pWrite = new HandlePtr(arena);
			Win32Err.checkFalse(win32_h.CreatePipe(cs, pRead.asSegment(), pWrite.asSegment(),
				MemorySegment.NULL, 0), cs);
			return new Pipe(new Handle(pRead.get()), new Handle(pWrite.get()));
		}
	}

	private final Handle readHandle;
	private final Handle writeHandle;

	private Pipe(Handle read, Handle write) {
		this.readHandle = read;
		this.writeHandle = write;
	}

	public Handle getReadHandle() {
		return readHandle;
	}

	public Handle getWriteHandle() {
		return writeHandle;
	}

	public void close() throws Exception {
		writeHandle.close();
		readHandle.close();
	}
}
