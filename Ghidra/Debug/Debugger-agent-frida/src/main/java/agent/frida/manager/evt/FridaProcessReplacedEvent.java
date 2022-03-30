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
package agent.frida.manager.evt;

import agent.frida.frida.FridaProcessInfo;
import agent.frida.manager.FridaState;

public class FridaProcessReplacedEvent extends AbstractFridaEvent<FridaProcessInfo> {

	public FridaProcessReplacedEvent(FridaProcessInfo info) {
		super(info);
	}
	
	@Override
	public FridaState newState() {
		// NB: it's very tempting to relay the info we have, but
		//   doing so fouls up a lot of the tests because the stopped
		//   message arrives ahead of breakpointHit
		
		//DebugProcessInfo pinfo = (DebugProcessInfo) getInfo();
		//return pinfo.process.GetState();
		return null;
	}

}
