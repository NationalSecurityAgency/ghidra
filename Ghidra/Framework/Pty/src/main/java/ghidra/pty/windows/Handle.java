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
import java.lang.ref.Cleaner;

import com.microsoft.win32.win32_h;

public class Handle implements AutoCloseable {
	private static final Cleaner CLEANER = Cleaner.create();

	protected static class State implements Runnable {
		protected final long handle;

		protected State(long handle) {
			this.handle = handle;
		}

		@Override
		public void run() {
			try (Arena arena = Arena.ofConfined()) {
				MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
				Win32Err.checkFalse(win32_h.CloseHandle(cs, MemorySegment.ofAddress(handle)), cs);
			}
		}
	}

	private final State state;
	private final Cleaner.Cleanable cleanable;

	public Handle(MemorySegment handle) {
		this.state = newState(handle.address());
		this.cleanable = CLEANER.register(this, state);
	}

	protected State newState(long handle) {
		return new State(handle);
	}

	@Override
	public void close() {
		cleanable.clean();
	}

	public MemorySegment asSegment() {
		return MemorySegment.ofAddress(state.handle);
	}
}
