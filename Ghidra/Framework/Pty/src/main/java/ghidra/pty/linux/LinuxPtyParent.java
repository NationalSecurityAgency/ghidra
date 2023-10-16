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
package ghidra.pty.linux;

import ghidra.pty.PtyParent;
import ghidra.pty.linux.PosixC.Winsize;

public class LinuxPtyParent extends LinuxPtyEndpoint implements PtyParent {
	LinuxPtyParent(int fd) {
		super(fd);
	}

	@Override
	public void setWindowSize(short cols, short rows) {
		Winsize.ByReference ws = new Winsize.ByReference();
		ws.ws_col = cols;
		ws.ws_row = rows;
		ws.write();
		PosixC.INSTANCE.ioctl(fd, Winsize.TIOCSWINSZ, ws.getPointer());
	}
}
