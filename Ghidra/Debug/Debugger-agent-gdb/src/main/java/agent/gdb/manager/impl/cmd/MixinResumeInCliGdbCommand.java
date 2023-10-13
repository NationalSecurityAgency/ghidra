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
public interface MixinResumeInCliGdbCommand<T> extends GdbCommand<T> {

	default Interpreter getInterpreter(GdbManagerImpl manager) {
		if (manager.hasCli()) {
			return Interpreter.CLI;
		}
		return Interpreter.MI2;
	}

	default boolean handleExpectingRunning(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (getInterpreter() == Interpreter.CLI) {
			/**
			 * As of gdb-14 (anticipated based on build from git commit b6ac461a), the MI2 console
			 * will no longer receive ^running from commands issued to the CLI that resume the
			 * target. I suspect only the console that issues the command is meant to receive the
			 * ^running result, and that the behavior we had been taking advantage of was in fact a
			 * bug. Thus, we should only expect the *running event. For the sake of older versions,
			 * when we receive ^running, we'll still claim it, so long as it comes before *running.
			 */
			if (evt instanceof GdbRunningEvent) {
				pending.claim(evt);
				return true;
			}
			else if (evt instanceof AbstractGdbCompletedCommandEvent) {
				pending.claim(evt);
				return false;
			}
		}
		else {
			/**
			 * This situation should only occur with versions before about 8.0, anyway, since those
			 * supporting new-ui should have the CLI. I guess a user could still pass -i mi2 to a
			 * modern version, which might induce this. In any case, if we're issuing the command
			 * from MI2, we should expect both the *running event and the ^running result.
			 */
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
		}
		return false;
	}

	default void completeOnRunning(GdbPendingCommand<?> pending) {
		// See comments in handleExpectingRunning
		if (getInterpreter() == Interpreter.CLI) {
			pending.findSingleOf(GdbRunningEvent.class);
		}
		else { // MI2
			pending.checkCompletion(GdbCommandRunningEvent.class);
		}
	}
}
