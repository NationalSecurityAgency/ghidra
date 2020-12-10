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
 * An "event" corresponding with GDB/MI commands
 * 
 * If using a PTY configured with local echo, the manager needs to recognize and ignore the commands
 * it issued. GDB/MI makes them easy to distinguish, because they start with "-".
 */
public class GdbCommandEchoEvent extends AbstractGdbEvent<String> {

	/**
	 * Construct a new "event", passing the tail through as information
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	public GdbCommandEchoEvent(CharSequence tail) throws GdbParseError {
		super(tail);
	}

	@Override
	protected String parseInfo(CharSequence tail) throws GdbParseError {
		return tail.toString();
	}
}
