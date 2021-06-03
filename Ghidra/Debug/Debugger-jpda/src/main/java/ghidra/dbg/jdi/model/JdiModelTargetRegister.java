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

import com.sun.jdi.Location;

import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.ConversionUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "RegisterDescriptor",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(
			name = TargetRegister.CONTAINER_ATTRIBUTE_NAME,
			type = JdiModelTargetRegisterContainer.class),
		@TargetAttributeType(type = Void.class)
	})
public class JdiModelTargetRegister extends JdiModelTargetObjectImpl implements TargetRegister {

	protected final String name;
	protected Address addr;

	public JdiModelTargetRegister(JdiModelTargetObject parent, String name, boolean isElement) {
		super(parent, name, name, isElement);
		this.name = name;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			CONTAINER_ATTRIBUTE_NAME, parent, //
			LENGTH_ATTRIBUTE_NAME, Long.SIZE //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay() //
		), "Initialized");

		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> init() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		if (name == null) {
			return super.getDisplay();
		}
		return addr == null ? name : name + ":" + addr;
	}

	public byte[] readRegister(Location location) {
		Address oldval = (Address) getCachedAttribute(VALUE_ATTRIBUTE_NAME);
		addr = JdiModelTargetLocation.getAddressFromLocation(impl, location);

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			VALUE_ATTRIBUTE_NAME, addr //
		), "Initialized");
		setModified(!addr.equals(oldval));

		byte[] bytes =
			ConversionUtils.bigIntegerToBytes(getBitLength() / 8, addr.getOffsetAsBigInteger());
		return bytes;
	}

}
