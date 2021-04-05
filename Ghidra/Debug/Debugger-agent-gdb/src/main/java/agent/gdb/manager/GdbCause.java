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
package agent.gdb.manager;

import agent.gdb.manager.impl.GdbPendingCommand;

/**
 * Identifies the cause of an event emitted by GDB
 * 
 * <p>
 * This is not a concept native to GDB. Rather, it is a means to distinguish events that result from
 * commands issued by the {@link GdbManager} from those issued by the user or some other means. For
 * example, a call to {@link GdbManager#addInferior()} will emit a
 * {@link GdbEventsListener#inferiorAdded(GdbInferior, GdbCause)} event, identifying the
 * {@link GdbPendingCommand} as the cause. However, a call to {@link GdbManager#console(String)}
 * issuing an "add-inferior" command will emit the same event, but the cause will be
 * {@link GdbCause.Causes#UNCLAIMED}.
 */
public interface GdbCause {
	public enum Causes implements GdbCause {
		UNCLAIMED;
	}
}
