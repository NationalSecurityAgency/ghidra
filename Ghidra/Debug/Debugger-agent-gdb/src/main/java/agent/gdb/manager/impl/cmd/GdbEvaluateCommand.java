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
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.GdbPendingCommand;

/**
 * Implementation of {@link GdbInferior#evaluate(String)}
 */
public class GdbEvaluateCommand extends AbstractGdbCommandWithThreadAndFrameId<String> {
	private static final String MI2_CMD = "-data-evaluate-expression";
	// 6 accounts for digits in threadId and frameId. 999 each should be plenty....
	public static final int MAX_EXPR_LEN = GdbManagerImpl.MAX_CMD_LEN - MI2_CMD.length() -
		MI2_THREAD_PREFIX.length() - MI2_FRAME_PREFIX.length() - 6;
	private final String expression;

	public GdbEvaluateCommand(GdbManagerImpl manager, Integer threadId, Integer frameId,
			String expression) {
		super(manager, threadId, frameId);
		this.expression = expression;
	}

	@Override
	protected String encode(String threadPart, String framePart) {
		return MI2_CMD + threadPart + framePart + " \"" +
			StringEscapeUtils.escapeJava(expression) + '"';
	}

	@Override
	public String complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		return done.assumeValue();
	}
}
