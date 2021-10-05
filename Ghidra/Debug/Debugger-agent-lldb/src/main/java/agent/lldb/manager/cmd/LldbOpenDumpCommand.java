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
package agent.lldb.manager.cmd;

import java.util.Map;

import SWIG.SBThread;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.AbstractLldbCompletedCommandEvent;
import agent.lldb.manager.evt.LldbProcessCreatedEvent;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbProcess#openDump(String)}
 */
public class LldbOpenDumpCommand extends AbstractLldbCommand<SBThread> {

	private LldbProcessCreatedEvent created = null;
	private boolean completed = false;
	private Map<String, ?> args;

	public LldbOpenDumpCommand(LldbManagerImpl manager, Map<String, ?> args) {
		super(manager);
		this.args = args;
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof AbstractLldbCompletedCommandEvent && pending.getCommand().equals(this)) {
			completed = true;
		}
		else if (evt instanceof LldbProcessCreatedEvent) {
			created = (LldbProcessCreatedEvent) evt;
		}
		return completed && (created != null);
	}

	@Override
	public SBThread complete(LldbPendingCommand<?> pending) {
		return null;
	}

	@Override
	public void invoke() {

		String f = (String) args.get("TraceOrDump");
		if (f.startsWith("/")) {
			f = f.substring(1);
		}
		f = f.replace("/", "\\");

		DebugClient client = manager.getClient();
		client.openDumpFileWide(f);
		manager.waitForEventEx();
	}
}
