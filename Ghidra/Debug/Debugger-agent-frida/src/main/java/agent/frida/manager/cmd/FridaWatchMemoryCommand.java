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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Map;

import com.google.gson.JsonElement;

import agent.frida.manager.impl.FridaManagerImpl;
import ghidra.util.Msg;

public class FridaWatchMemoryCommand extends AbstractFridaCommand<Void> {
	
	private Map<String, ?> arguments;

	public FridaWatchMemoryCommand(FridaManagerImpl manager, Map<String, ?> arguments) {
		super(manager);
		this.arguments = arguments;
	}

	@Override
	public void invoke() {
		String addr = (String) arguments.get("Address");
		if (!addr.startsWith("0x")) {
			addr = "0x" + addr;
		}
		Long size = (Long) arguments.get("Size");
		String cmd = "MemoryAccessMonitor.enable(" +
				"{ base: ptr(" + addr + "), " +
				"  size: " + size + " }, " +
				"{ ";		
		try {
			String onAccess = (String) arguments.get("OnAccess");
			FileInputStream fis = new FileInputStream(new File(onAccess));
			byte[] bytes = fis.readAllBytes();
			String str = new String(bytes);
			cmd += str + "});";
		}
		catch (IOException e) {
			e.printStackTrace();
			return;
		}

		manager.loadPermanentScript(this, (String) arguments.get("Name"), cmd);
	}

	@Override
	public void parseSpecifics(JsonElement element) {
		Msg.info(this, element);
		manager.unloadPermanentScript(getName());
	}
}
