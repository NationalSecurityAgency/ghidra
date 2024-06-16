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

import com.sun.jna.Memory;
import com.sun.jna.ptr.IntByReference;

import ghidra.pty.Pty;
import ghidra.pty.unix.PosixC.Ioctls;
import ghidra.util.Msg;

public class UnixPty implements Pty {

	static final PosixC LIB_POSIX = PosixC.INSTANCE;

	private final int aparent;
	private final int achild;
	private boolean closed = false;

	private final UnixPtyParent parent;
	private final UnixPtyChild child;

	public static UnixPty openpty(Ioctls ioctls) throws IOException {
		// TODO: Support termp and winp?
		IntByReference p = new IntByReference();
		IntByReference c = new IntByReference();
		Memory n = new Memory(1024);
		Util.INSTANCE.openpty(p, c, n, null, null);
		return new UnixPty(ioctls, p.getValue(), c.getValue(), n.getString(0));
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

	@Override
	public synchronized void close() throws IOException {
		if (closed) {
			return;
		}
		child.closeStreams();
		parent.closeStreams();
		LIB_POSIX.close(achild);
		LIB_POSIX.close(aparent);
		closed = true;
	}
}
