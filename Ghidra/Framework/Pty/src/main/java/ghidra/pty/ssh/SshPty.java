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

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSchException;

import ghidra.pty.*;

public class SshPty implements Pty {
	private final ChannelExec channel;
	private final OutputStream out;
	private final InputStream in;

	private final SshPtyParent parent;
	private final SshPtyChild child;

	public SshPty(ChannelExec channel) throws JSchException, IOException {
		this.channel = channel;

		out = channel.getOutputStream();
		in = channel.getInputStream();

		parent = new SshPtyParent(channel, out, in);
		child = new SshPtyChild(channel, out, in);
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
	public void close() throws IOException {
		channel.disconnect();
	}
}
