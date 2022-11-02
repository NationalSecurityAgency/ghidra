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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;

import agent.frida.model.iface2.FridaModelTargetAvailableProcess;
import agent.frida.model.iface2.FridaModelTargetAvailableProcessesContainer;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "AvailableProcess",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class FridaModelTargetAvailableProcessImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetAvailableProcess {

	protected static String keyAttachable(String pid) {
		return PathUtils.makeKey(pid);
	}

	protected final String pid;
	protected final String name;
	private Integer base = 10;

	public FridaModelTargetAvailableProcessImpl(FridaModelTargetAvailableProcessesContainer parent, String pid,
			String name) {
		super(parent.getModel(), parent, keyAttachable(pid), name);
		this.name = name;
		this.pid = pid;

		this.changeAttributes(List.of(), List.of(), Map.of(//
			PID_ATTRIBUTE_NAME, Long.parseLong(pid, 10), //
			DISPLAY_ATTRIBUTE_NAME, getDisplay() //
		), "Initialized");
	}

	public FridaModelTargetAvailableProcessImpl(FridaModelTargetAvailableProcessesContainer parent, String pid) {
		super(parent.getModel(), parent, keyAttachable(pid), "Attachable");
		this.pid = pid;
		this.name = "";

		this.changeAttributes(List.of(), List.of(), Map.of(//
			PID_ATTRIBUTE_NAME, Long.parseLong(pid, 10), //
			DISPLAY_ATTRIBUTE_NAME, keyAttachable(pid) //
		), "Initialized");
	}

	@TargetAttributeType(name = PID_ATTRIBUTE_NAME, hidden = true)
	@Override
	public Long getPid() {
		return Long.parseLong(pid);
	}

	@Override
	public String getDisplay() {
		Long p = Long.decode(pid);
		String pidstr = "";
		if (base == 16) {
			pidstr = "0x" + Long.toHexString(p);
		} else {
			pidstr = pid;
		}
		return "[" + pidstr + "] : " + name.trim();
	}
	
	public void setBase(Object value) {
		this.base = (Integer) value;
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay()//
		), "Started");
	}

}
