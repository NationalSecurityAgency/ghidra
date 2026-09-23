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

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import com.microsoft.win32._COORD;
import com.microsoft.win32.win32_h;

import ghidra.pty.*;

public class ConPty implements Pty {
	private final Pipe pipeToChild;
	private final Pipe pipeFromChild;
	private final PseudoConsoleHandle pseudoConsoleHandle;
	private boolean closed = false;

	private final ConPtyParent parent;
	private final ConPtyChild child;

	public static ConPty openpty(short cols, short rows) {
		// Create communication channels

		Pipe pipeToChild = Pipe.createPipe();
		Pipe pipeFromChild = Pipe.createPipe();

		// Close the child-connected ends after creating the pseudoconsole
		// Keep the parent-connected ends, because we're the parent

		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			HandlePtr phPC = new HandlePtr(arena);
			MemorySegment size = _COORD.allocate(arena);
			_COORD.X(size, cols);
			_COORD.Y(size, rows);
			Win32Err.checkHResult(win32_h.CreatePseudoConsole(cs, size,
				pipeToChild.getReadHandle().asSegment(),
				pipeFromChild.getWriteHandle().asSegment(),
				0, phPC.asSegment()), cs);
			return new ConPty(pipeToChild, pipeFromChild, new PseudoConsoleHandle(phPC.get()));
		}
	}

	public ConPty(Pipe pipeToChild, Pipe pipeFromChild, PseudoConsoleHandle pseudoConsoleHandle) {
		this.pipeToChild = pipeToChild;
		this.pipeFromChild = pipeFromChild;
		this.pseudoConsoleHandle = pseudoConsoleHandle;

		// TODO: See if this can all be combined with named pipes.
		// Would be nice if that's sufficient to support new-ui

		this.parent = new ConPtyParent(pipeToChild.getWriteHandle(), pipeFromChild.getReadHandle(),
			pseudoConsoleHandle);
		this.child = new ConPtyChild(pipeFromChild.getWriteHandle(), pipeToChild.getReadHandle(),
			pseudoConsoleHandle);
	}

	@Override
	public PtyParent getParent() {
		return parent;
	}

	@Override
	public PtyChild getChild() {
		return child;
	}

	@Override
	public synchronized void close() throws IOException {
		if (closed) {
			return;
		}
		try {
			pseudoConsoleHandle.close();
			pipeToChild.close();
			pipeFromChild.close();
		}
		catch (IOException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e);
		}
		closed = true;
	}
}
