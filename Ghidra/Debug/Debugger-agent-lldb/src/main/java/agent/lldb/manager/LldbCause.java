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
package agent.lldb.manager;

/**
 * Identifies the cause of an event emitted by lldb
 * 
 * This is not a concept native to lldb. Rather, it is a means to distinguish events that result
 * from commands issued by the {@link LldbManager} from those issued by the user or some other means.
 * For example, a call to {@link LldbManager#addProcess()} will emit a
 * {@link LldbEventsListener#processAdded(LldbProcess, LldbCause)} event, identifying the
 * {@link LldbPendingCommand} as the cause.
 */
public interface LldbCause {
	public enum Causes implements LldbCause {
		UNCLAIMED;
	}
}
