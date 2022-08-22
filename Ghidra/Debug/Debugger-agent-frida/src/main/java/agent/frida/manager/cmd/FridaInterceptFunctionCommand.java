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

import java.io.*;
import java.util.Map;

import com.google.gson.JsonElement;

import agent.frida.manager.impl.FridaManagerImpl;
import ghidra.util.Msg;

public class FridaInterceptFunctionCommand extends AbstractFridaCommand<Void> {
	
	private String address;
	private Map<String, ?> arguments;

	public FridaInterceptFunctionCommand(FridaManagerImpl manager, String address, Map<String, ?> arguments) {
		super(manager);
		this.address = address;
		this.arguments = arguments;
	}

	@Override
	public void invoke() {
		String cmd = "Interceptor.attach(ptr(" + address + "), {";
		try {
			String onEnter = (String) arguments.get("OnEnter");
			FileInputStream fis;
			if (!onEnter.isEmpty()) {
				fis = new FileInputStream(new File(onEnter));
				byte[] bytes = fis.readAllBytes();
				String str = new String(bytes);
				cmd += str + ",";
			} 
			String onLeave = (String) arguments.get("OnLeave");
			if (!onLeave.isEmpty()) {
				fis = new FileInputStream(new File(onLeave));
				byte[] bytes = fis.readAllBytes();
				String str = new String(bytes);
				cmd += str + ",";
			}
			cmd = cmd.substring(0, cmd.length()-1) + "});";
		}
		catch (IOException e) {
			e.printStackTrace();
			return;
		}

		manager.loadPermanentScript(this, (String) arguments.get("Name"), cmd);
	}

	@Override
	public void parseSpecifics(JsonElement element) {
		Msg.info(this, element.getAsString());
	}
}
