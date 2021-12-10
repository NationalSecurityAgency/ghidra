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
package agent.lldb.manager.evt;

import SWIG.SBEvent;
import SWIG.SBStream;
import agent.lldb.lldb.DebugProcessInfo;
import ghidra.util.Msg;

/**
 * The event corresponding with SBProcess.eBroadcastBitSTDERR & SBProcess.eBroadcastBitSTDOUT 
 */
public class LldbConsoleOutputEvent extends AbstractLldbEvent<DebugProcessInfo> {

	private int mask;
	private String text;

	public LldbConsoleOutputEvent(DebugProcessInfo info) {
		super(info);
		this.mask = 0;
		this.text = SBEvent.GetCStringFromEvent(info.event);
		SBStream stream = new SBStream();
		boolean success = info.event.GetDescription(stream);
		if (success) {
			Msg.info(this, stream.GetData());
			if (text == null) {
				text = stream.GetData();
			}
		}
	}

	public LldbConsoleOutputEvent(int mask, String text) {
		super(null);
		this.mask = mask;
		this.text = text;
	}

	public String getOutput() {
		return text;
	}

	public int getMask() {
		return mask;
	}
}
