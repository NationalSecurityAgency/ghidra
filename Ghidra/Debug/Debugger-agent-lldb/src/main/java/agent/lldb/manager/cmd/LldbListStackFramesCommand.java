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

import SWIG.SBFrame;
import SWIG.SBThread;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListStackFramesCommand extends AbstractLldbCommand<Map<String, SBFrame>> {
	protected final SBThread thread;
	private Map<String, SBFrame> result;

	public LldbListStackFramesCommand(LldbManagerImpl manager, SBThread thread) {
		super(manager);
		this.thread = thread;
	}

	@Override
	public Map<String, SBFrame> complete(LldbPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		result = new HashMap<>();
		long n = thread.GetNumFrames();
		for (int i = 0; i < n; i++) {
			SBFrame frame = thread.GetFrameAtIndex(i);
			result.put(DebugClient.getId(frame), frame);
		}
	}
}
