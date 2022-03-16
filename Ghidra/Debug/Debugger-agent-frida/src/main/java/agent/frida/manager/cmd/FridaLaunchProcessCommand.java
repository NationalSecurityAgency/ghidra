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
package agent.frida.manager.cmd;

import java.util.ArrayList;
import java.util.List;

import agent.frida.frida.FridaClient;
import agent.frida.manager.*;
import agent.frida.manager.evt.AbstractFridaCompletedCommandEvent;
import agent.frida.manager.evt.FridaProcessCreatedEvent;
import agent.frida.manager.impl.FridaManagerImpl;

/**
 * Implementation of {@link FridaProcess#launch(String)}
 */
public class FridaLaunchProcessCommand extends AbstractFridaCommand<FridaThread> {

	private FridaProcessCreatedEvent created = null;
	private boolean completed = false;
	private String fileName;
	private List<String> args;
	private List<String> envp;
	private List<String> pathsIO;
	private String wdir;
	private long flags;
	private boolean stopAtEntry;

	public FridaLaunchProcessCommand(FridaManagerImpl manager, String fileName, List<String> args) {
		this(manager, fileName, args, null, null, "", 0L, true);
	}

	public FridaLaunchProcessCommand(FridaManagerImpl manager, String fileName, List<String> args,
			List<String> envp,
			List<String> pathsIO, String workingDirectory, long flags, boolean stopAtEntry) {
		super(manager);
		this.fileName = fileName;
		this.args = args == null ? new ArrayList<>() : args;
		this.envp = envp == null ? new ArrayList<>() : envp;
		this.pathsIO = pathsIO;
		if (pathsIO == null) {
			this.pathsIO = new ArrayList<>();
			this.pathsIO.add("");
			this.pathsIO.add("");
			this.pathsIO.add("");
		}
		this.wdir = workingDirectory;
		this.flags = flags;
		this.stopAtEntry = stopAtEntry;
	}

	@Override
	public boolean handle(FridaEvent<?> evt, FridaPendingCommand<?> pending) {
		if (evt instanceof AbstractFridaCompletedCommandEvent && pending.getCommand().equals(this)) {
			completed = true;
		}
		else if (evt instanceof FridaProcessCreatedEvent) {
			created = (FridaProcessCreatedEvent) evt;
		}
		return completed && (created != null);
	}

	@Override
	public FridaThread complete(FridaPendingCommand<?> pending) {
		return manager.getCurrentThread();
	}

	@Override
	public void invoke() {
		FridaClient client = manager.getClient();
		//client.createProcess(client.getLocalServer(), fileName);
		client.createProcess(client.getLocalServer(), fileName, args, envp, pathsIO, wdir, flags,
			stopAtEntry);
	}
}
