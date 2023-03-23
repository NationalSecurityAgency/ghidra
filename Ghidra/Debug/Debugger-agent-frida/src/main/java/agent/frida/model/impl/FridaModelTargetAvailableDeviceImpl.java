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

import agent.frida.model.iface2.FridaModelTargetAvailableDevice;
import agent.frida.model.iface2.FridaModelTargetAvailableDevicesContainer;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "AvailableDevice",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class FridaModelTargetAvailableDeviceImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetAvailableDevice {

	protected static String keyAttachable(String id) {
		return PathUtils.makeKey(id);
	}

	protected final String id;
	protected final String name;

	public FridaModelTargetAvailableDeviceImpl(FridaModelTargetAvailableDevicesContainer parent,
			String id,
			String name) {
		super(parent.getModel(), parent, keyAttachable(id), name);
		this.name = name;
		this.id = id;

		this.changeAttributes(List.of(), List.of(), Map.of(//
			ID_ATTRIBUTE_NAME, id, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay() //
		), "Initialized");
	}

	public FridaModelTargetAvailableDeviceImpl(FridaModelTargetAvailableDevicesContainer parent,
			String id) {
		super(parent.getModel(), parent, keyAttachable(id), "Attachable");
		this.id = id;
		this.name = "";

		this.changeAttributes(List.of(), List.of(), Map.of(//
			ID_ATTRIBUTE_NAME, id, //
			DISPLAY_ATTRIBUTE_NAME, keyAttachable(id) //
		), "Initialized");
	}

	@TargetAttributeType(name = ID_ATTRIBUTE_NAME, hidden = true)
	@Override
	public String getId() {
		return id;
	}

	@Override
	public String getDisplay() {
		return "[" + id + "] : " + name.trim();
	}

	@Override
	public void setBase(Object value) {
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay()//
		), "Started");
	}

}
