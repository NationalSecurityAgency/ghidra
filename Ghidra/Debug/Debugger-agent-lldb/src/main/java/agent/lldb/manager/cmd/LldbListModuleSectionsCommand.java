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

import SWIG.SBModule;
import SWIG.SBSection;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListModuleSectionsCommand extends AbstractLldbCommand<Map<String, SBSection>> {
	protected final SBModule module;
	private Map<String, SBSection> result;

	public LldbListModuleSectionsCommand(LldbManagerImpl manager, SBModule module) {
		super(manager);
		this.module = module;
	}

	@Override
	public Map<String, SBSection> complete(LldbPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		result = new HashMap<>();
		long n = module.GetNumSections();
		for (int i = 0; i < n; i++) {
			SBSection section = module.GetSectionAtIndex(i);
			result.put(DebugClient.getId(section), section);
		}
	}
}
