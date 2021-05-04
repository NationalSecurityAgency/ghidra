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
package agent.gdb.manager.impl;

import java.io.*;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.junit.Ignore;

import agent.gdb.manager.GdbManager;
import agent.gdb.pty.PtyFactory;
import agent.gdb.pty.PtySession;
import agent.gdb.pty.linux.LinuxPty;
import agent.gdb.pty.linux.LinuxPtyFactory;
import ghidra.util.Msg;

@Ignore("Need compatible GDB version for CI")
public class JoinedGdbManagerTest extends AbstractGdbManagerTest {
	protected class ReaderThread extends Thread {
		@Override
		public void run() {
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(ptyUserGdb.getParent().getInputStream()));
			String line;
			try {
				while (gdb != null && null != (line = reader.readLine())) {
					Msg.debug(this, "USERGDB: " + line);
				}
			}
			catch (IOException e) {
				Msg.debug(this, "Error reading USERGDB line: " + e);
			}
		}
	}

	protected LinuxPty ptyUserGdb;
	protected PtySession gdb;

	@Override
	protected PtyFactory getPtyFactory() {
		// TODO: Choose by host OS
		return new LinuxPtyFactory();
	}

	@Override
	protected CompletableFuture<Void> startManager(GdbManager manager) {
		try {
			ptyUserGdb = LinuxPty.openpty();
			manager.start(null);
			Msg.debug(this, "Starting GDB and invoking new-ui mi2 " + manager.getMi2PtyName());

			gdb = ptyUserGdb.getChild()
					.session(new String[] { GdbManager.DEFAULT_GDB_CMD }, Map.of());
			new ReaderThread().start();
			PrintWriter gdbCmd = new PrintWriter(ptyUserGdb.getParent().getOutputStream());
			gdbCmd.println("new-ui mi2 " + manager.getMi2PtyName());
			gdbCmd.flush();
			return manager.runRC();
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	protected void stopManager() throws IOException {
		if (gdb != null) {
			gdb.destroyForcibly();
			gdb = null;
		}
		if (ptyUserGdb != null) {
			ptyUserGdb.close();
		}
	}
}
