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
import agent.gdb.manager.evt.GdbThreadSelectedEvent;
import agent.gdb.manager.impl.*;

public class GdbSetActiveFrameCommand extends AbstractGdbCommandWithThreadId<Void> {
	private final Integer frameId;
	private final boolean internal;

	/**
	 * Select the given thread and frame
	 * 
	 * @param manager the manager to execute the command
	 * @param threadId the desired thread Id
	 * @param frameId the desired frame level
	 * @param internal true to prevent announcement of the change
	 */
	public GdbSetActiveFrameCommand(GdbManagerImpl manager, Integer threadId, int frameId,
			boolean internal) {
		super(manager, threadId);
		this.frameId = frameId;
		this.internal = internal;
	}

	@Override
	protected String encode(String threadPart) {
		return "-interpreter-exec" + threadPart + " console \"frame " + frameId + "\"";
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (super.handle(evt, pending)) {
			return true;
		}
		else if (evt instanceof GdbThreadSelectedEvent) {
			pending.claim(evt);
		}
		return false;
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandDoneEvent.class);
		return null;
	}

	@Override
	public boolean isFocusInternallyDriven() {
		return internal;
	}
}
