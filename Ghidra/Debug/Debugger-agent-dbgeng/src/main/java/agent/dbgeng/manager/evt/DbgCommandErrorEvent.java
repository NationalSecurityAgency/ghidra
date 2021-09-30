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
package agent.dbgeng.manager.evt;

import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgState;

public class DbgCommandErrorEvent extends AbstractDbgCompletedCommandEvent {

	/**
	 * Construct a new event using the given error message
	 * 
	 * @param message the message
	 * @return the new event
	 */
	public static DbgEvent<?> fromMessage(String message) {
		return new DbgCommandErrorEvent(message);
	}

	protected DbgCommandErrorEvent() {
		super();
	}

	protected DbgCommandErrorEvent(String message) {
		super(message);
	}

	@Override
	public DbgState newState() {
		return DbgState.STOPPED;
	}
}
