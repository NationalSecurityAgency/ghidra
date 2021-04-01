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
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = "Attachable", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetAttachable
		extends DefaultTargetObject<TargetObject, GdbModelTargetAvailableContainer>
		implements TargetAttachable {

	public static final String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";
	// TODO: DESCRIPTION, TYPE, USER?

	protected static String indexAttachable(GdbProcessThreadGroup process) {
		return PathUtils.makeIndex(process.getPid());
	}

	protected static String keyAttachable(GdbProcessThreadGroup process) {
		return PathUtils.makeKey(indexAttachable(process));
	}

	protected static String computeDisplay(GdbProcessThreadGroup process, Integer base) {
		if (base == 16) {
			return String.format("0x%x %s", process.getPid(), process.getDescription());
		}
		return String.format("%d %s", process.getPid(), process.getDescription());
	}

	private GdbProcessThreadGroup process;
	protected long pid;
	protected String display;

	public GdbModelTargetAttachable(GdbModelImpl impl, GdbModelTargetAvailableContainer parent,
			GdbProcessThreadGroup process) {
		super(impl, parent, keyAttachable(process), "Attachable");
		this.process = process;
		this.pid = process.getPid();
		this.display = computeDisplay(process, 10);

		this.changeAttributes(List.of(), List.of(), Map.of( //
			PID_ATTRIBUTE_NAME, pid, //
			DISPLAY_ATTRIBUTE_NAME, display //
		), "Initialized");
	}

	@TargetAttributeType(name = PID_ATTRIBUTE_NAME, hidden = true)
	public long getPid() {
		return pid;
	}

	@Override
	public String getDisplay() {
		return display;
	}

	public void setBase(Object value) {
		this.display = computeDisplay(process, (Integer) value);
		this.changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, display //
		), "Initialized");
	}

}
