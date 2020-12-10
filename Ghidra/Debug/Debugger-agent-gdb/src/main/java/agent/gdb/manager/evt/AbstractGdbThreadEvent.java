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

import agent.gdb.manager.parsing.GdbParsingUtils;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;

/**
 * A base class for GDB events that involve a thread ID (including inferior ID)
 */
public abstract class AbstractGdbThreadEvent extends AbstractGdbEventWithFields {
	private final int tid;
	private final int iid;

	/**
	 * Construct a new event by parsing the tail for information
	 * 
	 * The thread ID and thread group ID must be specified by GDB in the "id" and "group-id" fields,
	 * respectively.
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	public AbstractGdbThreadEvent(CharSequence tail) throws GdbParseError {
		super(tail);
		this.tid = Integer.parseInt(getInfo().getString("id"));
		this.iid = GdbParsingUtils.parseInferiorId(getInfo().getString("group-id"));
	}

	/**
	 * Get the thread ID
	 * 
	 * @return the thread ID
	 */
	public int getThreadId() {
		return tid;
	}

	/**
	 * Get the inferior ID
	 * 
	 * @return the inferior ID
	 */
	public int getInferiorId() {
		return iid;
	}
}
