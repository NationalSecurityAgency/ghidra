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
package ghidra.pty.macos;

import ghidra.pty.unix.PosixC.Ioctls;
import ghidra.pty.unix.UnixPtySessionLeader;

public enum MacosIoctls implements Ioctls {
	INSTANCE;

	@Override
	public Class<? extends UnixPtySessionLeader> leaderClass() {
		return MacosPtySessionLeader.class;
	}

	@Override
	public long TIOCSCTTY() {
		return 0x20007461L;
	}

	@Override
	public long TIOCSWINSZ() {
		return 0x80087467L;
	}
}
