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

import org.apache.commons.text.StringEscapeUtils;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.evt.AbstractGdbCompletedCommandEvent;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.*;

/**
 * Implementation of {@link GdbInferior#evaluate(String)}
 */
public class GdbEvaluateCommand extends AbstractGdbCommandWithThreadAndFrameId<String> {
	private final String expression;

	public GdbEvaluateCommand(GdbManagerImpl manager, Integer threadId, Integer frameId,
			String expression) {
		super(manager, threadId, frameId);
		this.expression = expression;
	}

	@Override
	protected String encode(String threadPart, String framePart) {
		return "-data-evaluate-expression" + threadPart + framePart + " \"" +
			StringEscapeUtils.escapeJava(expression) + '"';
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}

	@Override
	public String complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		return done.assumeValue();
	}
}
