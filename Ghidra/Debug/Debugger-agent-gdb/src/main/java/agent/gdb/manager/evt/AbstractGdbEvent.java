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

import agent.gdb.manager.GdbCause;
import agent.gdb.manager.GdbCause.Causes;
import agent.gdb.manager.GdbState;
import agent.gdb.manager.impl.GdbEvent;
import agent.gdb.manager.impl.GdbPendingCommand;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;

/**
 * A base class for GDB events
 *
 * @param <T> the type of information detailing the event
 */
public abstract class AbstractGdbEvent<T> implements GdbEvent<T> {
	private final T info;
	protected GdbCause cause = Causes.UNCLAIMED;
	protected boolean stolen = false;

	/**
	 * Construct a new event, parsing the tail for information
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	protected AbstractGdbEvent(CharSequence tail) throws GdbParseError {
		this.info = parseInfo(tail);
	}

	/**
	 * Construct a new event with the given information
	 * 
	 * @param info the information
	 */
	protected AbstractGdbEvent(T info) {
		this.info = info;
	}

	/**
	 * Parse the tail into the required information type
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @return the parsed information
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	protected abstract T parseInfo(CharSequence tail) throws GdbParseError;

	@Override
	public T getInfo() {
		return info;
	}

	@Override
	public void claim(GdbPendingCommand<?> cmd) {
		if (cause != Causes.UNCLAIMED) {
			throw new IllegalStateException("Event is already claimed by " + cause);
		}
		cause = cmd;
	}

	@Override
	public GdbCause getCause() {
		return cause;
	}

	@Override
	public void steal() {
		stolen = true;
	}

	@Override
	public boolean isStolen() {
		return stolen;
	}

	@Override
	public String toString() {
		return "<" + getClass().getSimpleName() + " " + info + " >";
	}

	@Override
	public GdbState newState() {
		return null;
	}
}
