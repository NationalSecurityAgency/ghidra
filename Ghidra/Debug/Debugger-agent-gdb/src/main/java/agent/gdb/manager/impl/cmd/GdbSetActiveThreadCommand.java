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

import agent.gdb.manager.evt.*;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;

public class GdbSetActiveThreadCommand extends AbstractGdbCommandWithThreadAndFrameId<Void> {
	private final boolean internal;

	/**
	 * Select the given thread and frame level
	 * 
	 * <p>
	 * To simply select a thread, you should use frame 0 as the default.
	 * 
	 * @param manager the manager to execute the command
	 * @param threadId the desired thread Id
	 * @param frameId the desired frame level
	 * @param internal true to prevent announcement of the change
	 */
	public GdbSetActiveThreadCommand(GdbManagerImpl manager, int threadId, Integer frameId,
			boolean internal) {
		super(manager, threadId, frameId);
		this.internal = internal;
	}

	@Override
	public String encode(String threadPart, String framePart) {
		/**
		 * Yes, it's a bit redundant to use {@code --thread} here, but this allows frame selection
		 * via {@code --frame} as well. Granted {@code -stack-select-frame} may be available, it
		 * doesn't appear to produce notifications, and so I've opted not to use it.
		 */
		return "-thread-select" + threadPart + framePart + " " + threadId;
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		else if (evt instanceof GdbThreadSelectedEvent) {
			pending.claim(evt);
		}
		return false;
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		GdbThreadSelectedEvent already = pending.getFirstOf(GdbThreadSelectedEvent.class);
		if (already != null) {
			return null;
		}
		// Otherwise, we just changed frames within a thread. Fire the event ourselves.
		GdbThreadImpl thread = manager.getThread(threadId);
		GdbMiFieldList fields = done.getInfo().getFieldList("frame");
		if (fields == null) { // Uhhh... I guess we'll have to do without
			return null;
		}
		GdbStackFrameImpl frame = GdbStackFrameImpl.fromFieldList(thread, fields);
		manager.doThreadSelected(thread, frame, done.getCause());
		return null;
	}

	@Override
	public boolean isFocusInternallyDriven() {
		return internal;
	}
}
