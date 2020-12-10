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
 * The event corresponding with "{@code ~""}" output records
 */
public class GdbConsoleOutputEvent extends AbstractGdbOutputEvent {

	/**
	 * Construct a new event, parsing the tail for information
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @return the new event
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	public static GdbConsoleOutputEvent fromMi2(CharSequence tail) throws GdbParseError {
		return new GdbConsoleOutputEvent(tail);
	}

	/**
	 * Construct a new event with the given output
	 * 
	 * @param output the line of output
	 * @return the new event
	 */
	public static GdbConsoleOutputEvent fromCli(String output) {
		return new GdbConsoleOutputEvent(output + "\n");
	}

	// Hidden in favor of named factory methods
	protected GdbConsoleOutputEvent(CharSequence tail) throws GdbParseError {
		super(tail);
	}

	// Hidden in favor of named factory methods, as this is easily called accidentally
	protected GdbConsoleOutputEvent(String output) {
		super(output);
	}
}
