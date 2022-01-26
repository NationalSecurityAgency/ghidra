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

import com.sun.jna.LastErrorException;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase.SECURITY_ATTRIBUTES;
import com.sun.jna.platform.win32.WinNT.HANDLEByReference;

public class Pipe {
	public static Pipe createPipe() {
		HANDLEByReference pRead = new HANDLEByReference();
		HANDLEByReference pWrite = new HANDLEByReference();

		if (!Kernel32.INSTANCE.CreatePipe(pRead, pWrite, new SECURITY_ATTRIBUTES(), 0)) {
			throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
		}
		return new Pipe(new Handle(pRead.getValue()), new Handle(pWrite.getValue()));
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
