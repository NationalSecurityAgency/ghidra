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
package ghidra.dbg.jdi.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.Method;

import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.TargetSection;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.AddressRange;

@TargetObjectSchemaInfo(
	name = "Section",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	})
public class JdiModelTargetSection extends JdiModelTargetObjectImpl implements //
		//TargetMemory,
		TargetMemoryRegion, TargetSection {

	protected final Method method;
	private AddressRange range;

	public JdiModelTargetSection(JdiModelTargetSectionContainer parent, Method method,
			boolean isElement) {
		super(parent, method.toString(), method, isElement);
		this.method = method;

		this.range = impl.getAddressRange(method);

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			MODULE_ATTRIBUTE_NAME, parent.getClassType(), //
			READABLE_ATTRIBUTE_NAME, true, //
			MEMORY_ATTRIBUTE_NAME, parent, TargetMemoryRegion.RANGE_ATTRIBUTE_NAME, range //
		), "Initialized");
	}

	public JdiModelTargetSection(JdiModelTargetSectionContainer parent) {
		super(parent);
		this.method = null;

		range = impl.defaultRange;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			MODULE_ATTRIBUTE_NAME, parent.getClassType(), //
			TargetMemoryRegion.RANGE_ATTRIBUTE_NAME, range //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		this.range = method == null ? impl.defaultRange : impl.getAddressRange(method);
		if (range != null) {
			changeAttributes(List.of(), List.of(), Map.of(), "Initialized");
		}

		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> init() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		if (method == null)
			return "NULL";
		JdiModelTargetReferenceType classType =
			((JdiModelTargetSectionContainer) parent).getClassType();
		return classType.getName() + ":" + method.signature();
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

}
