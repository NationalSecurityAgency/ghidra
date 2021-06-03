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
package agent.dbgeng.manager;

import agent.dbgeng.manager.cmd.DbgPendingCommand;

/**
 * Identifies the cause of an event emitted by dbgeng
 * 
 * This is not a concept native to dbgeng. Rather, it is a means to distinguish events that result
 * from commands issued by the {@link DbgManager} from those issued by the user or some other means.
 * For example, a call to {@link DbgManager#addProcess()} will emit a
 * {@link DbgEventsListener#processAdded(DbgProcess, DbgCause)} event, identifying the
 * {@link DbgPendingCommand} as the cause.
 */
public interface DbgCause {
	public enum Causes implements DbgCause {
		UNCLAIMED;
	}
}
