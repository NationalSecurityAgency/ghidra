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

import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;

/**
 * The event corresponding to "@{code =cmd-param-changed}"
 */
public class GdbParamChangedEvent extends AbstractGdbEventWithFields {
	private final String param;
	private final String value;

	/**
	 * Construct a new event by parsing the tail for information
	 * 
	 * <p>
	 * The param (name) and value must be specified by GDB.
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	public GdbParamChangedEvent(CharSequence tail) throws GdbParseError {
		super(tail);
		this.param = getInfo().getString("param");
		this.value = getInfo().getString("value");
	}

	/**
	 * Get the parameter name
	 * 
	 * @return the name
	 */
	public String getParam() {
		return param;
	}

	/**
	 * Get the parameter value
	 * 
	 * @return the value
	 */
	public String getValue() {
		return value;
	}
}
