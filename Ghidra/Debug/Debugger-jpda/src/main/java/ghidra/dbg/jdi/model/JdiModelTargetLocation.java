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

import com.sun.jdi.AbsentInformationException;
import com.sun.jdi.Location;
import com.sun.jdi.request.BreakpointRequest;
import com.sun.jdi.request.EventRequestManager;

import ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointInfo;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

@TargetObjectSchemaInfo(
	name = "Location",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(name = "Method", type = String.class, required = true, fixed = true),
		@TargetAttributeType(name = "Line", type = Integer.class, required = true, fixed = true),
		@TargetAttributeType(name = "Index", type = Long.class, required = true, fixed = true),
		@TargetAttributeType(name = "Address", type = String.class, required = true, fixed = true),
		@TargetAttributeType(type = Object.class) //
	})
public class JdiModelTargetLocation extends JdiModelTargetObjectImpl {

	public static String getUniqueId(Location obj) {
		return obj.toString() + ":" + obj.codeIndex();
	}

	protected final Location location;
	private JdiModelTargetReferenceType declaringType;
	private Address address;

	public JdiModelTargetLocation(JdiModelTargetObject parent, Location location,
			boolean isElement) {
		super(parent, getUniqueId(location), location, isElement);
		this.location = location;

		impl.registerMethod(location.method());

		this.address = getAddress();

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //	
			"Method", location.method().name(), //
			"Line", location.lineNumber(), //
			"Index", location.codeIndex(), //
			"Address", Long.toHexString(address.getOffset()) //
		), "Initialized");

	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		this.declaringType = (JdiModelTargetReferenceType) getInstance(location.declaringType());

		changeAttributes(List.of(), List.of(), Map.of( //
			"Declaring Type", declaringType //
		), "Initialized");

		try {
			String sourceName = location.sourceName();
			String sourcePath = location.sourcePath();
			changeAttributes(List.of(), List.of(), Map.of( //
				"Source Name", sourceName, //
				"Source Path", sourcePath //
			), "Initialized");
		}
		catch (AbsentInformationException e) {
			// Ignore
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> init() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		return location == null ? super.getDisplay()
				: location.toString() + " [" + Long.toHexString(address.getOffset()) + "]";
	}

	public Address getAddress() {
		if (address != null) {
			return address;
		}
		return getAddressFromLocation(impl, location);
	}

	public static Address getAddressFromLocation(JdiModelImpl impl, Location location) {
		AddressRange addressRange = impl.getAddressRange(location.method());
		if (addressRange == null) {
			return impl.getAddressSpace("ram").getAddress(-1L);
		}
		long codeIndex = location.codeIndex();
		return addressRange.getMinAddress().add(codeIndex < 0 ? 0 : codeIndex);

	}

	public JdiBreakpointInfo addBreakpoint() {
		EventRequestManager eventManager = location.virtualMachine().eventRequestManager();
		BreakpointRequest request = eventManager.createBreakpointRequest(location);
		request.enable();
		return new JdiBreakpointInfo(request);
	}

}
