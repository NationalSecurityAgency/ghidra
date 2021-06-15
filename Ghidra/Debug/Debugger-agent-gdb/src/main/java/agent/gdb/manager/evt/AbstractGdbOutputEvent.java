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

import java.io.PrintWriter;

import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;

/**
 * A base class for GDB output records
 */
public abstract class AbstractGdbOutputEvent extends AbstractGdbEventWithString {
	protected final Interpreter interpreter;

	/**
	 * Construct a new event, parsing the tail for information
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	public AbstractGdbOutputEvent(CharSequence tail) throws GdbParseError {
		super(tail);
		this.interpreter = Interpreter.MI2;
	}

	/**
	 * Construct a new event for the given output
	 * 
	 * @param output the output
	 */
	public AbstractGdbOutputEvent(String output) {
		super(output);
		this.interpreter = Interpreter.CLI;
	}

	/**
	 * Get the output
	 * 
	 * GDB includes explicit line terminators, so the output may not necessarily be a complete line.
	 * It should be printed using, e.g., {@link PrintWriter#print(String)}, not
	 * {@link PrintWriter#println(String)}.
	 * 
	 * @return the output
	 */
	public String getOutput() {
		return getInfo();
	}

	/**
	 * Get the interpreter that produced this output
	 * 
	 * @return the interpreter
	 */
	public Interpreter getInterpreter() {
		return interpreter;
	}
}
