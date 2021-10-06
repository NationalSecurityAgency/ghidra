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
package agent.gdb.manager.impl.cmd;

import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.evt.GdbThreadGroupRemovedEvent;
import agent.gdb.manager.impl.*;

public class GdbRemoveInferiorCommand extends AbstractGdbCommand<Void> {

	private final int id;

	public GdbRemoveInferiorCommand(GdbManagerImpl manager, int id) {
		super(manager);
		this.id = id;
	}

	@Override
	public String encode() {
		return "-remove-inferior i" + id;
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (super.handle(evt, pending)) {
			return true;
		}
		if (evt instanceof GdbThreadGroupRemovedEvent) {
			pending.claim(evt);
		}
		return false;
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandDoneEvent.class);
		return null;
	}
}
