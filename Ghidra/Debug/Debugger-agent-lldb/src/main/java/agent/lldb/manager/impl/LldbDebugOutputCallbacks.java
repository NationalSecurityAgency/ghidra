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
package agent.lldb.manager.impl;

import agent.lldb.lldb.DebugOutputCallbacks;
import agent.lldb.manager.evt.LldbConsoleOutputEvent;

public class LldbDebugOutputCallbacks implements DebugOutputCallbacks {
	private LldbManagerImpl manager;

	public LldbDebugOutputCallbacks(LldbManagerImpl manager) {
		this.manager = manager;
	}

	@Override
	public void output(int mask, String text) {
		manager.processEvent(new LldbConsoleOutputEvent(mask, text));
	}

}
