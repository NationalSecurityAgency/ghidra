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

import java.math.BigInteger;

import SWIG.*;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.*;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.util.Msg;

public class LldbRunToAddressCommand extends AbstractLldbCommand<Void> {

	private SBThread thread;
	private final BigInteger addr;

	public LldbRunToAddressCommand(LldbManagerImpl manager, SBThread thread, BigInteger addr) {
		super(manager);
		this.thread = thread;
		this.addr = addr;
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof AbstractLldbCompletedCommandEvent && pending.getCommand().equals(this)) {
			return evt instanceof LldbCommandErrorEvent ||
				!pending.findAllOf(LldbRunningEvent.class).isEmpty();
		}
		else if (evt instanceof LldbRunningEvent) {
			// Event happens no matter which interpreter received the command
			pending.claim(evt);
			return !pending.findAllOf(AbstractLldbCompletedCommandEvent.class).isEmpty();
		}
		return false;
	}

	@Override
	public void invoke() {
		if (thread == null || !thread.IsValid()) {
			thread = manager.getCurrentThread();
		}
		SBError error = new SBError();
		thread.RunToAddress(addr, error);
		if (!error.Success()) {
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, error.GetType() + " while running to address: " + stream.GetData());
		}
	}
}
