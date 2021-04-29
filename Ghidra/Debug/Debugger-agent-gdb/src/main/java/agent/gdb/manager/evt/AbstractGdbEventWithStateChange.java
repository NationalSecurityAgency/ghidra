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
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import agent.gdb.manager.reason.GdbReason;

/**
 * A base class for GDB events notifying of state changes
 * 
 * Subclasses must specify the state implied by GDB issuing the event. This base class will parse
 * the reason if it is given by GDB.
 */
public abstract class AbstractGdbEventWithStateChange extends AbstractGdbEventWithFields {
	private final GdbReason reason;

	/**
	 * Construct a new event, parsing the tail for information
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	public AbstractGdbEventWithStateChange(CharSequence tail) throws GdbParseError {
		super(tail);
		this.reason = GdbReason.getReason(getInfo());
	}

	/**
	 * If applicable, get the reason for the event
	 * 
	 * @return the reason, or {@link GdbReason.Reasons#NONE}
	 */
	public GdbReason getReason() {
		return reason;
	}

	@Override
	public abstract GdbState newState();
}
