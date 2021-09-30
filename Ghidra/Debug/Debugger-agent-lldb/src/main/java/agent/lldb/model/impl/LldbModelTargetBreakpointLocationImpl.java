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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "BreakpointLocation",
	attributes = {
		@TargetAttributeType(type = Void.class)
	})
public class LldbModelTargetBreakpointLocationImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetBreakpointLocation {

	protected static String keyLocation(SBBreakpointLocation loc) {
		return PathUtils.makeKey(DebugClient.getId(loc));
	}

	protected static String keyLocation(SBWatchpoint wpt) {
		return PathUtils.makeKey(DebugClient.getId(wpt) + ".0");
	}

	protected LldbModelTargetAbstractXpointSpec spec;
	protected SBBreakpointLocation loc;

	protected Address address;
	protected Integer length;
	protected String display;


	public LldbModelTargetBreakpointLocationImpl(LldbModelTargetAbstractXpointSpec spec,
			SBBreakpointLocation loc) {
		super(spec.getModel(), spec, keyLocation(loc), loc, "BreakpointLocation");
		this.spec = spec;
		this.loc = loc;

		doChangeAttributes("Initialization");
	}

	public LldbModelTargetBreakpointLocationImpl(LldbModelTargetAbstractXpointSpec spec,
			SBWatchpoint wpt) {
		super(spec.getModel(), spec, keyLocation(wpt), wpt, "BreakpointLocation");
		this.loc = null;

		address = getModel().getAddress("ram", wpt.GetWatchAddress().longValue());
		this.changeAttributes(List.of(), Map.of(
			SPEC_ATTRIBUTE_NAME, parent,
			ADDRESS_ATTRIBUTE_NAME, address,
			LENGTH_ATTRIBUTE_NAME, length = (int) wpt.GetWatchSize(),
			DISPLAY_ATTRIBUTE_NAME, display = getDescription(1)),
			"Initialization");
		placeLocations();
	}

	public String getDescription(int level) {
		Object modelObject = getModelObject();
		SBStream stream = new SBStream();
		DescriptionLevel detail = DescriptionLevel.swigToEnum(level);
		if (modelObject instanceof SBBreakpointLocation) {
			SBBreakpointLocation loc = (SBBreakpointLocation) getModelObject();
			loc.GetDescription(stream, detail);
		}
		if (modelObject instanceof SBWatchpoint) {
			SBWatchpoint wpt = (SBWatchpoint) getModelObject();
			wpt.GetDescription(stream, detail);
		}
		return stream.GetData();
	}

	protected void doChangeAttributes(String reason) {
		address = getModel().getAddress("ram", loc.GetLoadAddress().longValue());
		length = 1;
		this.changeAttributes(List.of(), Map.of(
			SPEC_ATTRIBUTE_NAME, parent,
			ADDRESS_ATTRIBUTE_NAME, address,
			LENGTH_ATTRIBUTE_NAME, length,
			DISPLAY_ATTRIBUTE_NAME, display = getDescription(1)),
			reason);
		placeLocations();
	}

	protected void placeLocations() {
		LldbModelTargetSession parentSession = getParentSession();
		Map<String, ? extends TargetObject> cachedElements = parentSession.getProcesses().getCachedElements();
		for (TargetObject obj : cachedElements.values()) {
			if (obj instanceof LldbModelTargetProcess) {
				LldbModelTargetProcessImpl process = (LldbModelTargetProcessImpl) obj;
				process.addBreakpointLocation(this);
			}
		}
	}

	@Override
	protected void doInvalidate(TargetObject branch, String reason) {
		removeLocations();
		super.doInvalidate(branch, reason);
	}

	protected void removeLocations() {
		TargetObject modelObject = getModel().getModelObject(getManager().getCurrentProcess());
		if (modelObject instanceof LldbModelTargetProcess) {
			LldbModelTargetProcess targetProcess = (LldbModelTargetProcess) modelObject;
			LldbModelTargetBreakpointLocationContainer locs = (LldbModelTargetBreakpointLocationContainer) targetProcess.getCachedAttribute("Breakpoints");			
			locs.removeBreakpointLocation(this);
		}
	}
	
	@Override
	public Integer getLength() {
		return length;
	}

	@Override
	public Address getAddress() {
		return address;
	}
	
	@Override
	public int getLocationId() {
		return loc.GetID();
	}
}
