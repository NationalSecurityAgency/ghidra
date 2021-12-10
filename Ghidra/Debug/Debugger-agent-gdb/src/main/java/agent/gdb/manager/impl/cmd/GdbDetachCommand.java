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

import java.util.ArrayList;
import java.util.Collection;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.evt.*;
import agent.gdb.manager.impl.*;

/**
 * Implementation of {@link GdbInferior#detach()}
 */
public class GdbDetachCommand extends AbstractGdbCommandWithThreadId<Void> {
	private final GdbInferiorImpl inferior;

	public GdbDetachCommand(GdbManagerImpl manager, GdbInferiorImpl inferior, Integer threadId) {
		super(manager, threadId);
		this.inferior = inferior;
	}

	@Override
	public String encode(String threadPart) {
		return "-target-detach" + threadPart;
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (super.handle(evt, pending)) {
			return true;
		}
		else if (evt instanceof GdbThreadExitedEvent) {
			pending.claim(evt);
		}
		else if (evt instanceof GdbThreadGroupExitedEvent) {
			pending.claim(evt);
		}
		return false;
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandDoneEvent.class);

		// GDB does not notify thread exit when detaching. At least not via GDB/MI
		// TODO: Copy on write instead?
		Collection<GdbThreadImpl> threads =
			new ArrayList<>(inferior.getKnownThreadsImpl().values());
		for (GdbThreadImpl t : threads) {
			manager.fireThreadExited(t.getId(), inferior, pending);
			t.remove();
		}
		return null;
	}
}
