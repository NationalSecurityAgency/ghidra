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

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import org.unix.*;

import ghidra.pty.Pty;
import ghidra.util.Msg;
import utility.function.ExceptionalSupplier;

public class UnixPty implements Pty {
	private final int aparent;
	private final int achild;
	private boolean closed = false;

	private final UnixPtyParent parent;
	private final UnixPtyChild child;

	public static UnixPty openpty(Ioctls ioctls) throws IOException {
		// TODO: Support termp and winp?		
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(UnixErr.LAYOUT);
			MemorySegment p = arena.allocate(pty_h.C_INT);
			MemorySegment c = arena.allocate(pty_h.C_INT);
			MemorySegment n = arena.allocate(pty_h.C_CHAR, 1024);
			UnixErr.checkLt0(pty_h.openpty(cs, p, c, n, MemorySegment.NULL, MemorySegment.NULL), cs);
			return new UnixPty(ioctls,
				p.get(pty_h.C_INT, 0),
				c.get(pty_h.C_INT, 0),
				n.getString(0));
		}
	}

	UnixPty(Ioctls ioctls, int aparent, int achild, String name) {
		Msg.debug(this, "New Pty: " + name + " at (" + aparent + "," + achild + ")");
		this.aparent = aparent;
		this.achild = achild;

		this.parent = new UnixPtyParent(ioctls, aparent);
		this.child = new UnixPtyChild(ioctls, achild, name);
	}

	@Override
	public UnixPtyParent getParent() {
		return parent;
	}

	@Override
	public UnixPtyChild getChild() {
		return child;
	}

	static class OnError implements AutoCloseable {
		Throwable error = null;

		public <T> T step(ExceptionalSupplier<T, Throwable> step) {
			T ret = null;
			try {
				ret = step.get();
			}
			catch (Throwable e) {
				if (error == null) {
					error = e;
				}
			}
			return ret;
		}

		@Override
		public void close() throws Exception {
			switch (error) {
				case null -> {
				}
				case Exception e -> throw e;
				default -> throw new RuntimeException(error);
			}
		}
	}

	@Override
	public synchronized void close() throws IOException {
		if (closed) {
			return;
		}
		child.closeStreams();
		parent.closeStreams();
		try (Arena arena = Arena.ofConfined(); OnError err = new OnError()) {
			MemorySegment cs = arena.allocate(UnixErr.LAYOUT);
			err.step(() -> UnixErr.checkLt0(unistd_h.close(cs, achild), cs));
			err.step(() -> UnixErr.checkLt0(unistd_h.close(cs, aparent), cs));
			closed = true;
		}
		catch (Exception e) {
			throw new IOException("Error closing pty", e);
		}
	}
}
