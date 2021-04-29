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
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;

/**
 * A marker and mixin for dealing with commands where resuming in a secondary (mi2) ui seems
 * problematic.
 * 
 * <p>
 * I'm not sure if it's a bug in GDB or Linux, or what, but if I attach to a target that doesn't
 * have a tty then resume (i.e., continue or step) from the mi2 interpreter, it seems I cannot use
 * "interrupt" from the primary (console) interpreter. So, for these resumes, I need to issue the
 * command from the console, allowing ^C to work.
 */
public interface MixinResumeInCliGdbCommand extends GdbCommand<Void> {

	default Interpreter getInterpreter(GdbManagerImpl manager) {
		if (manager.hasCli()) {
			return Interpreter.CLI;
		}
		return Interpreter.MI2;
	}

	default boolean handleExpectingRunning(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof GdbCommandRunningEvent) {
			pending.claim(evt);
			return pending.hasAny(GdbRunningEvent.class);
		}
		else if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true; // Not the expected Completed event 
		}
		else if (evt instanceof GdbRunningEvent) {
			// Event happens no matter which interpreter received the command
			pending.claim(evt);
			return pending.hasAny(GdbCommandRunningEvent.class);
		}
		return false;
	}

	default Void completeOnRunning(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandRunningEvent.class);
		return null;
	}
}
