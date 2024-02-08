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
package ghidra.pty.ssh;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSchException;

import ghidra.dbg.util.ShellUtils;
import ghidra.pty.PtyChild;
import ghidra.util.Msg;

public class SshPtyChild extends SshPtyEndpoint implements PtyChild {
	private String name;

	public SshPtyChild(ChannelExec channel, OutputStream outputStream, InputStream inputStream) {
		super(channel, outputStream, inputStream);
	}

	private String sttyString(Collection<TermMode> mode) {
		StringBuilder sb = new StringBuilder();
		if (mode.contains(Echo.OFF)) {
			sb.append("-echo ");
		}
		else if (mode.contains(Echo.ON)) {
			sb.append("echo ");
		}
		if (sb.isEmpty()) {
			return "";
		}
		return "stty " + sb + "&& ";
	}

	@Override
	public SshPtySession session(String[] args, Map<String, String> env, File workingDirectory,
			Collection<TermMode> mode) throws IOException {
		if (workingDirectory != null) {
			throw new UnsupportedOperationException();
		}
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
		String cmdStr = ShellUtils.generateLine(Arrays.asList(args));
		channel.setCommand(sttyString(mode) + envStr + cmdStr);
		try {
			channel.connect();
		}
		catch (JSchException e) {
			throw new IOException("SSH error", e);
		}
		return new SshPtySession(channel);
	}

	private String getTtyNameAndStartNullSession(Collection<TermMode> mode) throws IOException {
		// NB. UNIX sleep is only required to support integer durations
		channel.setCommand(sttyString(mode) +
			"sh -c 'tty && ctrlc() { echo; } && trap ctrlc INT && while true; do sleep " +
			Integer.MAX_VALUE + "; done'");
		try {
			channel.connect();
		}
		catch (JSchException e) {
			throw new IOException("SSH error", e);
		}
		byte[] buf = new byte[1024]; // Should be plenty
		for (int i = 0; i < 1024; i++) {
			int chr = inputStream.read();
			if (chr == '\n' || chr == -1) {
				return new String(buf, 0, i + 1, "UTF-8").trim();
			}
			buf[i] = (byte) chr;
		}
		throw new IOException("Expected pty name. Got " + new String(buf, 0, 1024, "UTF-8"));
	}

	@Override
	public String nullSession(Collection<TermMode> mode) throws IOException {
		if (name == null) {
			this.name = getTtyNameAndStartNullSession(mode);
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
