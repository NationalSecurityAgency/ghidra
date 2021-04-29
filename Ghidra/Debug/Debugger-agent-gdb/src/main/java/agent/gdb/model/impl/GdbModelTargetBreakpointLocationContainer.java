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

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointLocationContainer;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

/**
 * This is a container of links only, as a way to encode "affects" within the model
 */
@TargetObjectSchemaInfo(
	name = "BreakpointLocationContainer",
	canonicalContainer = true,
	attributes = {
		@TargetAttributeType(type = Void.class)
	})
public class GdbModelTargetBreakpointLocationContainer
		extends DefaultTargetObject<GdbModelTargetBreakpointLocation, GdbModelTargetInferior>
		implements TargetBreakpointLocationContainer {
	public static final String NAME = "Breakpoints";

	protected static String indexLoc(GdbModelTargetBreakpointLocation loc) {
		return loc.getSpecification().getIndex() + "," + loc.getIndex();
	}

	public GdbModelTargetBreakpointLocationContainer(GdbModelTargetInferior inferior) {
		super(inferior.impl, inferior, NAME, "BreakpointLocationContainer");
	}

	public void addBreakpointLocation(GdbModelTargetBreakpointLocation loc) {
		changeElements(List.of(), Map.of(indexLoc(loc), loc), "Added");
	}

	public void removeBreakpointLocation(GdbModelTargetBreakpointLocation loc) {
		changeElements(List.of(indexLoc(loc)), Map.of(), "Removed");
	}
}
