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

import java.util.HashMap;
import java.util.Map;

import SWIG.DynamicValueType;
import SWIG.SBValue;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListStackFrameRegistersCommand extends AbstractLldbCommand<Map<String, SBValue>> {
	protected final SBValue bank;
	private Map<String, SBValue> result;

	public LldbListStackFrameRegistersCommand(LldbManagerImpl manager, SBValue bank) {
		super(manager);
		this.bank = bank;
	}

	@Override
	public Map<String, SBValue> complete(LldbPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		result = new HashMap<>();
		long n = bank.GetNumChildren();
		for (int i = 0; i < n; i++) {
			SBValue child = bank.GetChildAtIndex(i, DynamicValueType.eDynamicCanRunTarget, true);
			result.put(DebugClient.getId(child), child);
		}
	}
}
