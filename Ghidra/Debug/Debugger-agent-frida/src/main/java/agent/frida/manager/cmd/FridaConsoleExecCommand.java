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

import com.google.gson.JsonElement;

import agent.frida.manager.FridaEvent;
import agent.frida.manager.FridaManager;
import agent.frida.manager.evt.AbstractFridaCompletedCommandEvent;
import agent.frida.manager.evt.FridaConsoleOutputEvent;
import agent.frida.manager.impl.FridaManagerImpl;

/**
 * Implementation of {@link FridaManager#console(String)} and similar
 */
public class FridaConsoleExecCommand extends AbstractFridaCommand<String> {
	public enum Output {
		CONSOLE, CAPTURE;
	}

	private String command;
	private Output to;

	public FridaConsoleExecCommand(FridaManagerImpl manager, String command, Output to) {
		super(manager);
		this.command = command;
		this.to = to;
	}

	@Override
	public boolean handle(FridaEvent<?> evt, FridaPendingCommand<?> pending) {
		if (evt instanceof AbstractFridaCompletedCommandEvent &&
			pending.getCommand().equals(this)) {
			return true;
		}
		else if (evt instanceof FridaConsoleOutputEvent && to == Output.CAPTURE) {
			pending.steal(evt);
		}
		return false;
	}

	@Override
	public String complete(FridaPendingCommand<?> pending) {
		if (to == Output.CONSOLE) {
			return null;
		}
		StringBuilder builder = new StringBuilder();
		for (FridaConsoleOutputEvent out : pending.findAllOf(FridaConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		return builder.toString();
	}

	@Override
	public void invoke() {
		if (!command.isEmpty()) {
			manager.loadScript(this, "exec", command);
		}
	}

	@Override
	public void parseSpecifics(JsonElement element) {
		String res = element.isJsonPrimitive() ? element.getAsString() : element.toString() + "\n";
		manager.getClient().processEvent(new FridaConsoleOutputEvent(0, res));
		//manager.getEventListeners().fire.consoleOutput(object+"\n", 0);		
	}

}
