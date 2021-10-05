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

import java.util.Map;

import SWIG.*;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.*;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.util.Msg;

/**
 * Implementation of {@link LldbThread#stepInstruction()}
 */
public class LldbStepCommand extends AbstractLldbCommand<Void> {

	private SBThread thread;
	private TargetStepKind kind;
	private Map<String, ?> args;
	private String lastCommand = "";

	public LldbStepCommand(LldbManagerImpl manager, SBThread thread, TargetStepKind kind,
			Map<String, ?> args) {
		super(manager);
		this.thread = thread;
		this.kind = kind;
		this.args = args;
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
		RunMode rm = RunMode.eOnlyThisThread;
		if (thread == null) {
			thread = manager.getCurrentThread();
			rm = RunMode.eAllThreads;
		}
		if (kind == null) {
			kind = (TargetStepKind) args.get("Kind");
		}
		SBError error = new SBError();
		switch (kind) {
			case INTO:
				thread.StepInstruction(false, error);
				break;
			case OVER:
				thread.StepInstruction(true, error);
				break;
			case LINE:
				thread.StepInto();
				break;
			case OVER_LINE:
				thread.StepOver(rm, error);
				break;
			case RETURN:
				thread.StepOut(error);
				break;
			case FINISH:
				thread.StepOutOfFrame(thread.GetSelectedFrame(), error);
				break;
			case ADVANCE:
				SBFileSpec file = (SBFileSpec) args.get("File");
				long line = (long) args.get("Line");
				error = thread.StepOverUntil(thread.GetSelectedFrame(), file, line);
				break;
			case EXTENDED:
				manager.execute(new LldbEvaluateCommand(manager, lastCommand));
				break;
			case SKIP:
			default:
				throw new UnsupportedOperationException("Step " + kind.name() + " not supported");
		}
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " while stepping");
		}
	}

	public String getLastCommand() {
		return lastCommand;
	}

	public void setLastCommand(String lastCommand) {
		this.lastCommand = lastCommand;
	}
}
