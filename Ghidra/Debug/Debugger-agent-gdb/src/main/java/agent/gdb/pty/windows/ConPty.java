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

import java.io.IOException;

import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinNT.HANDLEByReference;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.gdb.pty.*;
import agent.gdb.pty.windows.jna.ConsoleApiNative;
import agent.gdb.pty.windows.jna.ConsoleApiNative.COORD;

public class ConPty implements Pty {
	static final DWORD DW_ZERO = new DWORD(0);
	static final DWORD DW_ONE = new DWORD(1);
	static final DWORD PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = new DWORD(0x20016);
	static final DWORD EXTENDED_STARTUPINFO_PRESENT =
		new DWORD(Kernel32.EXTENDED_STARTUPINFO_PRESENT);
	private static final COORD SIZE = new COORD();
	static {
		SIZE.X = Short.MAX_VALUE;
		SIZE.Y = 1;
	}

	private final Pipe pipeToChild;
	private final Pipe pipeFromChild;
	private final PseudoConsoleHandle pseudoConsoleHandle;
	private boolean closed = false;

	private final ConPtyParent parent;
	private final ConPtyChild child;

	public static ConPty openpty() {
		// Create communication channels

		Pipe pipeToChild = Pipe.createPipe();
		Pipe pipeFromChild = Pipe.createPipe();

		// Close the child-connected ends after creating the pseudoconsole
		// Keep the parent-connected ends, because we're the parent

		HANDLEByReference lphPC = new HANDLEByReference();

		COMUtils.checkRC(ConsoleApiNative.INSTANCE.CreatePseudoConsole(
			SIZE,
			pipeToChild.getReadHandle().getNative(),
			pipeFromChild.getWriteHandle().getNative(),
			DW_ZERO,
			lphPC));

		return new ConPty(pipeToChild, pipeFromChild, new PseudoConsoleHandle(lphPC.getValue()));
	}

	public ConPty(Pipe pipeToChild, Pipe pipeFromChild, PseudoConsoleHandle pseudoConsoleHandle) {
		this.pipeToChild = pipeToChild;
		this.pipeFromChild = pipeFromChild;
		this.pseudoConsoleHandle = pseudoConsoleHandle;

		// TODO: See if this can all be combined with named pipes.
		// Would be nice if that's sufficient to support new-ui

		this.parent = new ConPtyParent(pipeToChild.getWriteHandle(), pipeFromChild.getReadHandle());
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
