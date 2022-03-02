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

public class FridaStalkThreadCommand extends AbstractFridaCommand<Void> {
	
	private Map<String, ?> arguments;
	private String tid;

	public FridaStalkThreadCommand(FridaManagerImpl manager, String tid, Map<String, ?> arguments) {
		super(manager);
		this.tid = tid;
		this.arguments = arguments;
	}

	@Override
	public void invoke() {
		String cmd = 
				"Stalker.follow(" + tid + ", {" +
				"   events: { " +
				"      call: " + arguments.get("EventCall") + "," +
				"      ret: " + arguments.get("EventRet") + "," +
				"      exec: " + arguments.get("EventExec") + "," +
				"      block: " + arguments.get("EventBlock") + "," +
				"      compile: " + arguments.get("EventCompile") +
				"   }, ";
		try {
			String onReceive = (String) arguments.get("OnReceive");
			String onCallSummary = (String) arguments.get("OnCallSummary");
			FileInputStream fis;
			if (!onReceive.isEmpty()) {
				fis = new FileInputStream(new File(onReceive));
			} else {
				fis = new FileInputStream(new File(onCallSummary));
			}
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
	}
}
