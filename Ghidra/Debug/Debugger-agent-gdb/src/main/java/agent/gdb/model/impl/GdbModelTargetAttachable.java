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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;

import agent.gdb.manager.GdbProcessThreadGroup;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

public class GdbModelTargetAttachable
		extends DefaultTargetObject<TargetObject, GdbModelTargetAvailableContainer>
		implements TargetAttachable<GdbModelTargetAttachable> {
	protected static final String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";
	// TODO: DESCRIPTION, TYPE, USER?

	protected static String indexAttachable(GdbProcessThreadGroup process) {
		return PathUtils.makeIndex(process.getPid());
	}

	protected static String keyAttachable(GdbProcessThreadGroup process) {
		return PathUtils.makeKey(indexAttachable(process));
	}

	protected static String computeDisplay(GdbProcessThreadGroup process) {
		return String.format("%d %s", process.getPid(), process.getDescription());
	}

	protected final long pid;
	protected final String display;

	public GdbModelTargetAttachable(GdbModelImpl impl, GdbModelTargetAvailableContainer parent,
			GdbProcessThreadGroup process) {
		super(impl, parent, keyAttachable(process), "Attachable");
		this.pid = process.getPid();
		this.display = computeDisplay(process);

		this.changeAttributes(List.of(), List.of(), Map.of( //
			PID_ATTRIBUTE_NAME, pid, //
			DISPLAY_ATTRIBUTE_NAME, display, //
			UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED //
		), "Initialized");
	}

	public long getPid() {
		return pid;
	}

	@Override
	public String getDisplay() {
		return display;
	}
}
