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
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.framework.plugintool.util.PluginException;
import ghidra.pty.Pty;
import ghidra.pty.PtySession;

public class RunBashInTerminalScript extends TerminalGhidraScript {
	@Override
	protected void runSession(Pty pty) throws IOException, PluginException {
		Map<String, String> env = new HashMap<>(System.getenv());
		env.put("TERM", "xterm-256color");
		PtySession session = pty.getChild().session(new String[] { "/usr/bin/bash" }, env);
		displayInTerminal(pty.getParent(), () -> {
			try {
				session.waitExited();
			}
			catch (InterruptedException e) {
				return;
			}
		});
	}
}
