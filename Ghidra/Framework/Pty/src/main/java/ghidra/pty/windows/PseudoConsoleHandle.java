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

import com.microsoft.win32._COORD;
import com.microsoft.win32.win32_h;

public class PseudoConsoleHandle extends Handle {

	protected static class PseudoConsoleState extends State {
		public PseudoConsoleState(long handle) {
			super(handle);
		}

		@Override
		public void run() {
			win32_h.ClosePseudoConsole(MemorySegment.ofAddress(handle));
		}
	}

	public PseudoConsoleHandle(MemorySegment handle) {
		super(handle);
	}

	@Override
	protected State newState(long handle) {
		return new PseudoConsoleState(handle);
	}

	public void resize(short rows, short cols) {
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			MemorySegment size = _COORD.allocate(arena);
			_COORD.X(size, cols);
			_COORD.Y(size, rows);
			Win32Err.checkHResult(win32_h.ResizePseudoConsole(cs, asSegment(), size), cs);
		}
	}
}
