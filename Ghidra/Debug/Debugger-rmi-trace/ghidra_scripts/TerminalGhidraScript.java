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
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.core.terminal.TerminalListener;
import ghidra.app.plugin.core.terminal.TerminalPlugin;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Terminal;
import ghidra.app.services.TerminalService;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.pty.*;

public class TerminalGhidraScript extends GhidraScript {

	protected TerminalService ensureTerminalService() throws PluginException {
		TerminalService termServ = state.getTool().getService(TerminalService.class);
		if (termServ != null) {
			return termServ;
		}
		state.getTool().addPlugin(TerminalPlugin.class.getName());
		return state.getTool().getService(TerminalService.class);
	}

	protected void displayInTerminal(PtyParent parent, Runnable waiter) throws PluginException {
		TerminalService terminalService = ensureTerminalService();
		try (Terminal term = terminalService.createWithStreams(Charset.forName("UTF-8"),
			parent.getInputStream(), parent.getOutputStream())) {
			term.addTerminalListener(new TerminalListener() {
				@Override
				public void resized(short cols, short rows) {
					parent.setWindowSize(cols, rows);
				}
			});
			waiter.run();
		}
	}

	protected void runSession(Pty pty) throws IOException, PluginException {
		Map<String, String> env = new HashMap<>(System.getenv());
		env.put("TERM", "xterm-256color");
		pty.getChild().nullSession();
		displayInTerminal(pty.getParent(), () -> {
			while (true) {
				try {
					Thread.sleep(100000);
				}
				catch (InterruptedException e) {
					return;
				}
			}
		});
	}

	@Override
	protected void run() throws Exception {
		PtyFactory factory = PtyFactory.local();
		try (Pty pty = factory.openpty()) {
			runSession(pty);
		}
	}
}
