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
package agent.gdb.pty.windows;

import java.lang.ref.Cleaner;

import com.sun.jna.LastErrorException;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT.HANDLE;

public class Handle implements AutoCloseable {
	private static final Cleaner CLEANER = Cleaner.create();

	protected static class State implements Runnable {
		protected final HANDLE handle;

		protected State(HANDLE handle) {
			this.handle = handle;
		}

		@Override
		public void run() {
			if (!Kernel32.INSTANCE.CloseHandle(handle)) {
				throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
			}
		}
	}

	private final State state;
	private final Cleaner.Cleanable cleanable;

	public Handle(HANDLE handle) {
		this.state = newState(handle);
		this.cleanable = CLEANER.register(this, state);
	}

	protected State newState(HANDLE handle) {
		return new State(handle);
	}

	@Override
	public void close() throws Exception {
		cleanable.clean();
	}

	public HANDLE getNative() {
		HANDLE handle = state.handle;
		if (handle == null) {
			throw new IllegalStateException("This handle is no longer valid");
		}
		return handle;
	}
}
