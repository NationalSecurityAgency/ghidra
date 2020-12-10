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
package agent.gdb.manager.evt;

import agent.gdb.manager.GdbState;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;

/**
 * The event corresponding with "{@code ^running}"
 */
public class GdbCommandRunningEvent extends AbstractGdbCompletedCommandEvent {

	/**
	 * Construct a new event, parsing the tail for information
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	public GdbCommandRunningEvent(CharSequence tail) throws GdbParseError {
		super(tail);
	}

	/**
	 * Construct a new event with no information
	 */
	public GdbCommandRunningEvent() {
		super(GdbMiFieldList.builder().build());
	}

	@Override
	public GdbState newState() {
		return null; // Let *running cause change, as it has more info.
	}
}
