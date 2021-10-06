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
package agent.gdb.manager.impl.cmd;

import java.util.*;

import agent.gdb.manager.GdbCause.Causes;
import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.breakpoint.GdbBreakpointInfo;
import agent.gdb.manager.breakpoint.GdbBreakpointLocation;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.GdbPendingCommand;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import ghidra.util.Msg;

/**
 * Implementation of {@link GdbInferior#listBreakpoints()}
 */
public class GdbListBreakpointsCommand
		extends AbstractGdbCommandWithThreadId<Map<Long, GdbBreakpointInfo>> {

	public GdbListBreakpointsCommand(GdbManagerImpl manager, Integer threadId) {
		super(manager, threadId);
	}

	@Override
	protected String encode(String threadPart) {
		return "-break-list" + threadPart;
	}

	@Override
	public Map<Long, GdbBreakpointInfo> complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		// Do not use GdbTable here, since col_names provide good IDs
		// Also, there are some bonus fields that don't appear in cells....
		GdbMiFieldList tbl = done.assumeBreakpointTable();
		GdbMiFieldList body = tbl.getFieldList("body");
		Set<Long> nums = new HashSet<>();
		Map<Long, GdbBreakpointInfo> allBreakpoints = manager.getKnownBreakpointsInternal();
		List<GdbBreakpointLocation> allLocs = GdbBreakpointInfo.parseLocations(body);
		for (Object bkpt : body.get("bkpt")) {
			GdbBreakpointInfo info =
				GdbBreakpointInfo.parseBkpt((GdbMiFieldList) bkpt, allLocs, null);
			nums.add(info.getNumber());
			GdbBreakpointInfo exists = allBreakpoints.get(info.getNumber());
			if (exists != null) {
				if (!exists.equals(info)) {
					// Need to update as if =breakpoint-modified
					Msg.warn(this, "Resync: Missed breakpoint modification: " + info);
					manager.doBreakpointModified(info, Causes.UNCLAIMED);
				}
				continue;
			}
			// Need to add as if =breakpoint-created
			Msg.warn(this, "Resync: Was missing breakpoint: " + info);
			manager.doBreakpointCreated(info, Causes.UNCLAIMED);
		}
		for (long num : new ArrayList<>(manager.getKnownBreakpoints().keySet())) {
			if (nums.contains(num)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove as if =breakpoint-deleted
			Msg.warn(this, "Resync: Had extra breakpoint: " + num);
			manager.doBreakpointDeleted(num, Causes.UNCLAIMED);
		}
		return manager.getKnownBreakpoints();
	}
}
