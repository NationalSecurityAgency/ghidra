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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import agent.frida.frida.FridaEng;
import agent.frida.manager.FridaCommand;
import agent.frida.manager.FridaEvent;
import agent.frida.manager.FridaScript;
import agent.frida.manager.FridaState;
import agent.frida.manager.evt.FridaCommandDoneEvent;
import agent.frida.manager.impl.FridaManagerImpl;
import ghidra.util.Msg;

/**
 * A base class for interacting with specific Frida commands
 *
 * @param <T> the type of object "returned" by the command
 */
public abstract class AbstractFridaCommand<T> implements FridaCommand<T> {
	protected final FridaManagerImpl manager;
	private String name;
	private FridaScript script;

	/**
	 * Construct a new command to be executed by the given manager
	 * 
	 * @param manager the manager to execute the command
	 */
	protected AbstractFridaCommand(FridaManagerImpl manager) {
		this.manager = manager;
	}

	@Override
	public boolean validInState(FridaState state) {
		return true; // With dual interpreters, shouldn't have to worry.
	}

	@Override
	public boolean handle(FridaEvent<?> evt, FridaPendingCommand<?> pending) {
		if (evt instanceof FridaCommandDoneEvent) {
			return pending.getCommand().equals(((FridaCommandDoneEvent) evt).getCmd());
		}
		return false;
	}

	@Override
	public T complete(FridaPendingCommand<?> pending) {
		return null;
	}

	@Override
	public void invoke() {
		// Nothing
	}
	

	@Override
	public void parse(String result, Object data) {
		JsonObject jobj = JsonParser.parseString(result).getAsJsonObject();
		if (jobj.has("type")) {
			String type = jobj.get("type").getAsString();
			if (type.equals("error")) {
				String desc = jobj.get("description").getAsString();
				manager.getEventListeners().fire.consoleOutput(desc+"\n", 0);		
				Msg.error(this, desc);
				return;
			}
		}
		if (jobj.has("payload")) {
			Object object = jobj.get("payload");
			if (!(object instanceof JsonPrimitive)) {
				manager.getEventListeners().fire.consoleOutput(object+" not a String\n", 0);		
				Msg.error(this, object);	
				return;
			} 
			
			String value = ((JsonPrimitive) object).getAsString();
			if (!value.startsWith("{")) {
				manager.getEventListeners().fire.consoleOutput(object+"\n", 0);		
				return;
			}
			JsonElement res = JsonParser.parseString(value);
			if (res instanceof JsonObject) {
				JsonObject keyValue = (JsonObject) res;
				JsonElement element = keyValue.get("key");
				if (element != null) {
					res = keyValue.get("value");
					String key = element.getAsString();
					if (!key.equals(name)) {
						manager.getEventListeners().fire.consoleOutput(res+"\n", 0);		
						return;
					}
				} else {
					manager.getEventListeners().fire.consoleOutput(object+"\n", 0);		
				}
			} else {
				manager.getEventListeners().fire.consoleOutput(object+"\n", 0);		
			}
			if ("[]".equals(res.toString())) {
				Msg.error(this, "nothing returned for "+this);
				return;
			}
			if (res instanceof JsonArray) {
				JsonArray arr = (JsonArray) res;
				for (JsonElement l : arr) {
					parseSpecifics(l);
				}
			} else {
				parseSpecifics(res);
			}
		}
		cleanup();
	}

	public void parseSpecifics(JsonElement object) {
		// Nothing
	}

	public void cleanup() {
		if (script != null) {
			FridaEng.unloadScript(script);
			FridaEng.disconnectSignal(script, script.getSignal());
			FridaEng.unref(script);
		}
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setScript(FridaScript script) {
		this.script = script;
	}

}
