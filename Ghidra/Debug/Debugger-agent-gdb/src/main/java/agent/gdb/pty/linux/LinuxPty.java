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

import java.io.IOException;
import java.nio.ByteBuffer;

import agent.gdb.pty.Pty;
import ghidra.util.Msg;
import jnr.ffi.Pointer;
import jnr.ffi.byref.IntByReference;
import jnr.posix.POSIX;
import jnr.posix.POSIXFactory;

public class LinuxPty implements Pty {
	static final POSIX LIB_POSIX = POSIXFactory.getNativePOSIX();

	private final int aparent;
	private final int achild;
	//private final String name;
	private boolean closed = false;

	private final LinuxPtyParent parent;
	private final LinuxPtyChild child;

	public static LinuxPty openpty() throws IOException {
		// TODO: Support termp and winp?
		IntByReference p = new IntByReference();
		IntByReference c = new IntByReference();
		Pointer n = Pointer.wrap(jnr.ffi.Runtime.getSystemRuntime(), ByteBuffer.allocate(1024));
		if (Util.INSTANCE.openpty(p, c, n, null, null) < 0) {
			int errno = LIB_POSIX.errno();
			throw new IOException(errno + ": " + LIB_POSIX.strerror(errno));
		}
		return new LinuxPty(p.intValue(), c.intValue(), n.getString(0));
	}

	LinuxPty(int aparent, int achild, String name) {
		Msg.debug(this, "New Pty: " + name + " at (" + aparent + "," + achild + ")");
		this.aparent = aparent;
		this.achild = achild;
		//this.name = name;

		this.parent = new LinuxPtyParent(aparent);
		this.child = new LinuxPtyChild(achild, name);
	}

	@Override
	public LinuxPtyParent getParent() {
		return parent;
	}

	@Override
	public LinuxPtyChild getChild() {
		return child;
	}

	@Override
	public synchronized void close() throws IOException {
		if (closed) {
			return;
		}
		int result;
		result = LIB_POSIX.close(achild);
		if (result < 0) {
			throw new IOException(LIB_POSIX.strerror(LIB_POSIX.errno()));
		}
		result = LIB_POSIX.close(aparent);
		if (result < 0) {
			throw new IOException(LIB_POSIX.strerror(LIB_POSIX.errno()));
		}
		closed = true;
	}
}
