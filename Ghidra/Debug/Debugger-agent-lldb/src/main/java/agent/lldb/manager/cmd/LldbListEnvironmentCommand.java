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

import java.util.*;

import SWIG.*;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListEnvironmentCommand extends AbstractLldbCommand<Map<String, String>> {

	private SBTarget session;
	private Map<String, String> keyValues = new HashMap<>();

	public LldbListEnvironmentCommand(LldbManagerImpl manager, SBTarget session) {
		super(manager);
		this.session = session;
	}

	@Override
	public Map<String, String> complete(LldbPendingCommand<?> pending) {
		return keyValues;
	}

	@Override
	public void invoke() {
		SBEnvironment env = session.GetEnvironment();
		for (int i = 0; i < env.GetNumValues(); i++) {
			String key = env.GetNameAtIndex(i);
			String value = env.GetValueAtIndex(i);
			keyValues.put(key, value);
		}
	}

}
