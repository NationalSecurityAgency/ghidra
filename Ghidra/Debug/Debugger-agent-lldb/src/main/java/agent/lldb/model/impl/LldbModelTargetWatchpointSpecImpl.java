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

import java.util.*;

import SWIG.*;
import agent.lldb.model.iface2.LldbModelTargetBreakpointContainer;
import agent.lldb.model.iface2.LldbModelTargetBreakpointLocation;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "BreakpointSpec",
	elements = { //
		@TargetElementType(type = LldbModelTargetBreakpointLocationImpl.class) //
	},
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class LldbModelTargetWatchpointSpecImpl extends LldbModelTargetAbstractXpointSpec {

	private List<LldbModelTargetBreakpointLocationImpl> locs = new ArrayList<>();

	public LldbModelTargetWatchpointSpecImpl(LldbModelTargetBreakpointContainer breakpoints,
			Object info) {
		super(breakpoints, info, "WatchpointSpec");
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBWatchpoint wpt = (SBWatchpoint) getModelObject();
		DescriptionLevel detail = DescriptionLevel.swigToEnum(level);
		wpt.GetDescription(stream, detail);
		String data = stream.GetData();
		return data.equals("No value") ? getName() : data;
	}

	protected TargetBreakpointKindSet computeKinds(Object from) {
		return TargetBreakpointKindSet.of(TargetBreakpointKind.READ, TargetBreakpointKind.WRITE);
	}

	public void updateInfo(Object info, String reason) {
		if (!valid) {
			return;
		}
		setModelObject(info);
		updateAttributesFromInfo(reason);

		SBWatchpoint wpt = (SBWatchpoint) getModelObject();
		locs.add(new LldbModelTargetBreakpointLocationImpl(this, wpt));
		setElements(locs, Map.of(), "Refreshed");
	}

	public void updateAttributesFromInfo(String reason) {
		SBWatchpoint wpt = (SBWatchpoint) getModelObject();
		this.changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, display = getDescription(0), //
			KINDS_ATTRIBUTE_NAME, kinds = computeKinds(wpt), //
			ENABLED_ATTRIBUTE_NAME, enabled = wpt.IsEnabled(), //
			EXPRESSION_ATTRIBUTE_NAME, "" //
		), reason);
		this.changeAttributes(List.of(), List.of(), Map.of( //
			BPT_TYPE_ATTRIBUTE_NAME, "Hardware", //
			BPT_DISP_ATTRIBUTE_NAME, wpt.IsEnabled(), //
			BPT_VALID_ATTRIBUTE_NAME, wpt.IsValid(), //
			BPT_TIMES_ATTRIBUTE_NAME, wpt.GetHitCount() //
		), reason);
	}

	@Override
	public LldbModelTargetBreakpointLocation findLocation(Object object) {
		return locs.get(0);
	}

}
