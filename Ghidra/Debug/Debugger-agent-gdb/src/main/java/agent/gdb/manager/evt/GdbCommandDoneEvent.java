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

import java.util.ArrayList;
import java.util.List;

import agent.gdb.manager.GdbInferiorThreadGroup;
import agent.gdb.manager.GdbProcessThreadGroup;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import agent.gdb.manager.parsing.GdbParsingUtils;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import ghidra.util.Msg;

/**
 * The event corresponding with "{@code ^done}"
 */
public class GdbCommandDoneEvent extends AbstractGdbCompletedCommandEvent {
	private static Long parseLong(String nullable) {
		return nullable == null ? null : Long.parseLong(nullable);
	}

	/**
	 * Construct a new event, parsing the tail for information
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	public GdbCommandDoneEvent(CharSequence tail) throws GdbParseError {
		super(tail);
	}

	/**
	 * Assume inferior groups are specified, and get those groups' IDs
	 * 
	 * @return the list of inferior thread-group IDs
	 */
	public List<GdbInferiorThreadGroup> assumeInferiorGroups() {
		List<GdbMiFieldList> groups = getInfo().getListOf(GdbMiFieldList.class, "groups");
		List<GdbInferiorThreadGroup> iids = new ArrayList<>();
		for (GdbMiFieldList groupInfo : groups) {
			String gid = groupInfo.getString("id");
			if (!gid.startsWith("i")) {
				continue;
			}
			int iid = GdbParsingUtils.parseInferiorId(gid);
			String type = groupInfo.getString("type");
			String pid = groupInfo.getString("pid");
			String exitCode = groupInfo.getString("exit-code");
			String executable = groupInfo.getString("executable");
			iids.add(new GdbInferiorThreadGroup(iid, type, parseLong(pid), parseLong(exitCode),
				executable));
		}
		return iids;
	}

	/**
	 * Assume process groups are specified, and get those processes' descriptions
	 * 
	 * @return the list of (available) process thread-groups
	 */
	public List<GdbProcessThreadGroup> assumeProcessGroups() {
		List<GdbMiFieldList> groups = getInfo().getListOf(GdbMiFieldList.class, "groups");
		List<GdbProcessThreadGroup> pids = new ArrayList<>();
		for (GdbMiFieldList groupInfo : groups) {
			if (!"process".equals(groupInfo.getString("type"))) {
				Msg.error(this, "Unexpected type in available thread groups: " + groupInfo);
				// TODO: If necessary, communicate type and id in the returned list
				continue;
			}
			String gid = groupInfo.getString("id");
			String desc = groupInfo.getString("description");
			try {
				pids.add(new GdbProcessThreadGroup(Integer.parseInt(gid), desc));
			}
			catch (NumberFormatException e) {
				Msg.error(this, "Unexpected group id in available thread groups: " + groupInfo);
			}
		}
		return pids;
	}

	/**
	 * Assume threads are specified, and get those threads' IDs
	 * 
	 * @return the list of thread IDs
	 */
	public List<Integer> assumeThreadIds() {
		List<GdbMiFieldList> threads = getInfo().getListOf(GdbMiFieldList.class, "threads");
		List<Integer> tids = new ArrayList<>();
		for (GdbMiFieldList threadInfo : threads) {
			String tid = threadInfo.getString("id");
			try {
				tids.add(Integer.parseInt(tid));
			}
			catch (NumberFormatException e) {
				Msg.error(this, "Unexpected thread id in: " + threadInfo);
			}
		}
		return tids;
	}

	/**
	 * Assume a value is specified, and get it as a string
	 * 
	 * @return the value
	 */
	public String assumeValue() {
		return getInfo().getString("value");
	}

	/**
	 * Check if a value is specified, and get it as a string
	 * 
	 * @return the value, or null if not specified
	 */
	public String maybeValue() {
		if (getInfo().containsKey("value")) {
			return assumeValue();
		}
		return null;
	}

	/**
	 * Assume an "OSDataTable" is specified, and get that table
	 * 
	 * @return the parsed, but not processed, table
	 */
	public GdbMiFieldList assumeOSDataTable() {
		return getInfo().getFieldList("OSDataTable");
	}

	/**
	 * Assume a register name list is specified, and get that list
	 * 
	 * @return the parsed, but not processed, list
	 */
	public List<String> assumeRegisterNameList() {
		return getInfo().getListOf(String.class, "register-names");
	}

	/**
	 * Assume a register value list is specified, and get that list
	 * 
	 * @return the parsed, but not processed, list
	 */
	public List<GdbMiFieldList> assumeRegisterValueList() {
		return getInfo().getListOf(GdbMiFieldList.class, "register-values");
	}

	/**
	 * Assume a memory contents list is specified, and get that list
	 * 
	 * @return the parsed, but not processed, list
	 */
	public List<GdbMiFieldList> assumeMemoryContentsList() {
		return getInfo().getListOf(GdbMiFieldList.class, "memory");
	}

	/**
	 * Assume a thread info list is specified, and get that list
	 * 
	 * @return the parsed, but not processed, list
	 */
	public List<GdbMiFieldList> assumeThreadInfoList() {
		return getInfo().getListOf(GdbMiFieldList.class, "threads");
	}

	/**
	 * Assume a breakpoint table is specified, and get that table
	 * 
	 * @return the parsed, but not processed, table
	 */
	public GdbMiFieldList assumeBreakpointTable() {
		return getInfo().getFieldList("BreakpointTable");
	}

	/**
	 * Assume a stack is specified, and get that stack
	 * 
	 * @return the parsed, but not processed, stack
	 */
	public GdbMiFieldList assumeStack() {
		return getInfo().getFieldList("stack");
	}
}
