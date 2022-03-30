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
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import agent.frida.frida.FridaClient;
import agent.frida.frida.FridaClient.DebugCreateFlags;
import agent.frida.manager.*;
import agent.frida.manager.evt.AbstractFridaCompletedCommandEvent;
import agent.frida.manager.evt.FridaProcessCreatedEvent;
import agent.frida.manager.impl.FridaManagerImpl;

/**
 * Implementation of {@link FridaTarget#launch(String)}
 */
public class FridaLaunchProcessWithOptionsCommand extends AbstractFridaCommand<FridaThread> {

	private FridaProcessCreatedEvent created = null;
	private boolean completed = false;
	private String fileName;
	private List<String> args;
	private List<String> envp;
	private List<String> pathsIO;
	private String wdir;
	private long flags;
	private boolean stopAtEntry;

	public FridaLaunchProcessWithOptionsCommand(FridaManagerImpl manager, Map<String, ?> args) {
		super(manager);
		this.fileName = (String) args.get("File");
		String argstr = (String) args.get("Args");
		this.args = argstr.equals("") ? new ArrayList<String>() : Arrays.asList(argstr.split(" "));
		String envstr = (String) args.get("Env");
		this.envp = envstr.equals("") ? new ArrayList<String>() : Arrays.asList(envstr.split(" "));
		this.pathsIO = new ArrayList<>();
		this.pathsIO.add((String)args.get("STDIN"));
		this.pathsIO.add((String)args.get("STDOUT"));
		this.pathsIO.add((String)args.get("STDERR"));
		this.wdir = (String) args.get("Dir");
		this.flags = DebugCreateFlags.LAUNCH_DEFAULT.getMask();
		this.stopAtEntry = false;
		if ((boolean) args.get("Exec")) {
			flags |= DebugCreateFlags.LAUNCH_EXEC.getMask();
		}
		if ((boolean) args.get("BreakOnLaunch")) {
			flags |= DebugCreateFlags.LAUNCH_DEBUG.getMask();
		}
		if ((boolean) args.get("BreakOnEntry")) {
			flags |= DebugCreateFlags.LAUNCH_STOP_AT_ENTRY.getMask();
			stopAtEntry = true;
		}
		if ((boolean) args.get("ASLR")) {
			flags |= DebugCreateFlags.LAUNCH_DISABLE_ASLR.getMask();
		}
		if ((boolean) args.get("STDIO")) {
			flags |= DebugCreateFlags.LAUNCH_DISABLE_STDIO.getMask();
		}
		if ((boolean) args.get("NewTTY")) {
			flags |= DebugCreateFlags.LAUNCH_IN_TTY.getMask();
		}
		if ((boolean) args.get("Shell")) {
			flags |= DebugCreateFlags.LAUNCH_IN_SHELL.getMask();
		}
		if ((boolean) args.get("NewGroup")) {
			flags |= DebugCreateFlags.LAUNCH_IN_SEP_GROUP.getMask();
		}
		if ((boolean) args.get("ExitRace")) {
			flags |= DebugCreateFlags.LAUNCH_DONT_SET_EXIT_STATUS.getMask();
		}
		if ((boolean) args.get("Detach")) {
			flags |= DebugCreateFlags.LAUNCH_DETACH_ON_ERROR.getMask();
		}
		if ((boolean) args.get("ExpandArgs")) {
			flags |= DebugCreateFlags.LAUNCH_SHELL_EXPAND_ARGS.getMask();
		}
		if ((boolean) args.get("CloseTTY")) {
			flags |= DebugCreateFlags.LAUNCH_CLOSE_TTY_ON_EXIT.getMask();
		}
		if ((boolean) args.get("Inherit")) {
			flags |= DebugCreateFlags.LAUNCH_INHERIT_FROM_PARENT.getMask();
		}
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
		client.createProcess(client.getLocalServer(), fileName, args, envp, pathsIO, wdir, flags,
			stopAtEntry);
	}
}
