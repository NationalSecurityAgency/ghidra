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
package ghidra.app.plugin.core.debug.stack;

import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.cmd.TypedBackgroundCommand;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.trace.model.Trace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A command to unwind as much of the stack as possible and annotate the resulting frame in the
 * dynamic listing
 */
public class UnwindStackCommand extends TypedBackgroundCommand<Trace> {

	private final PluginTool tool;
	private final DebuggerCoordinates where;

	public UnwindStackCommand(PluginTool tool, DebuggerCoordinates where) {
		super("Unwind Stack", false, true, false);
		this.tool = tool;
		this.where = where;
	}

	@Override
	public boolean applyToTyped(Trace obj, TaskMonitor monitor) {
		try {
			StackUnwinder unwinder = new StackUnwinder(tool, where.getPlatform());
			int prevParamSize = 0;
			for (AnalysisUnwoundFrame<WatchValue> frame : unwinder.frames(where.frame(0),
				monitor)) {
				UnwindInfo info = frame.getUnwindInfo();
				if (info != null && info.error() == null) {
					frame.applyToListing(prevParamSize, monitor);
					prevParamSize = info.computeParamSize();
				}
				else {
					tool.setStatusInfo(frame.getError().getMessage());
				}
			}
			return true;
		}
		catch (CancelledException e) {
			return true;
		}
	}
}
