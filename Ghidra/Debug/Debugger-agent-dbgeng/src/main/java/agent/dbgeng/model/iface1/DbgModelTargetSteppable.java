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
package agent.dbgeng.model.iface1;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.DbgManager.ExecSuffix;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetSteppable;

/**
 * An interface which indicates this object is capable of launching targets.
 * 
 * The targets this launcher creates ought to appear in its successors.
 * 
 * @param <T> type for this
 */
public interface DbgModelTargetSteppable extends DbgModelTargetObject, TargetSteppable {

	default ExecSuffix convertToDbg(TargetStepKind kind) {
		switch (kind) {
			case FINISH:
				return ExecSuffix.FINISH;
			case INTO:
				return ExecSuffix.STEP_INSTRUCTION;
			case LINE:
				return ExecSuffix.STEP;
			case OVER:
				return ExecSuffix.NEXT_INSTRUCTION;
			case OVER_LINE:
				return ExecSuffix.NEXT;
			case RETURN:
				return ExecSuffix.RETURN;
			case UNTIL:
				return ExecSuffix.UNTIL;
			case EXTENDED:
				return ExecSuffix.EXTENDED;
			default:
				throw new AssertionError();
		}
	}

	@Override
	default CompletableFuture<Void> step(TargetStepKind kind) {
		DbgThread thread = getManager().getCurrentThread();
		switch (kind) {
			case SKIP:
				throw new UnsupportedOperationException(kind.name());
			case ADVANCE: // Why no exec-advance in dbgeng?
				return thread.console("advance");
			default:
				if (this instanceof DbgModelTargetThread) {
					DbgModelTargetThread targetThread = (DbgModelTargetThread) this;
					return getModel().gateFuture(targetThread.getThread().step(convertToDbg(kind)));
				}
				if (this instanceof DbgModelTargetProcess) {
					DbgModelTargetProcess targetProcess = (DbgModelTargetProcess) this;
					return getModel()
							.gateFuture(targetProcess.getProcess().step(convertToDbg(kind)));
				}
				return getModel().gateFuture(thread.step(convertToDbg(kind)));
		}
	}

	@Override
	default CompletableFuture<Void> step(Map<String, ?> args) {
		DbgThread thread = getManager().getCurrentThread();
		return getModel().gateFuture(thread.step(args));
	}

}
