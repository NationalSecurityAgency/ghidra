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
package agent.gdb.pty.ssh;

import java.io.*;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.help.UnsupportedOperationException;

import agent.gdb.pty.PtyChild;
import ch.ethz.ssh2.Session;
import ghidra.util.Msg;

public class SshPtyChild extends SshPtyEndpoint implements PtyChild {
	private String name;
	private final Session session;

	public SshPtyChild(Session session) {
		super(null, null);
		this.session = session;
	}

	@Override
	public SshPtySession session(String[] args, Map<String, String> env) throws IOException {
		/**
		 * TODO: This syntax assumes a UNIX-style shell, and even among them, this may not be
		 * universal. This certainly works for my version of bash :)
		 */
		String envStr = env == null
				? ""
				: env.entrySet()
						.stream()
						.map(e -> e.getKey() + "=" + e.getValue())
						.collect(Collectors.joining(" ")) +
					" ";
		String cmdStr = Stream.of(args).collect(Collectors.joining(" "));
		session.execCommand(envStr + cmdStr);
		return new SshPtySession(session);
	}

	private String getTtyNameAndStartNullSession() throws IOException {
		// NB. Using [InputStream/Buffered]Reader will close my stream. Cannot do that.
		InputStream stdout = session.getStdout();
		// NB. UNIX sleep is only required to support integer durations
		session.execCommand(
			"sh -c 'tty && cltrc() { echo; } && trap ctrlc INT && while true; do sleep " +
				Integer.MAX_VALUE + "; done'",
			"UTF-8");
		byte[] buf = new byte[1024]; // Should be plenty
		for (int i = 0; i < 1024; i++) {
			int chr = stdout.read();
			if (chr == '\n' || chr == -1) {
				return new String(buf, 0, i + 1).trim();
			}
			buf[i] = (byte) chr;
		}
		throw new IOException("Remote tty name exceeds 1024 bytes?");
	}

	@Override
	public String nullSession() throws IOException {
		if (name == null) {
			this.name = getTtyNameAndStartNullSession();
			if ("".equals(name)) {
				throw new IOException("Could not determine child remote tty name");
			}
		}
		Msg.debug(this, "Remote SSH pty: " + name);
		return name;
	}

	@Override
	public InputStream getInputStream() {
		throw new UnsupportedOperationException("The child is not local");
	}

	@Override
	public OutputStream getOutputStream() {
		throw new UnsupportedOperationException("The child is not local");
	}
}
