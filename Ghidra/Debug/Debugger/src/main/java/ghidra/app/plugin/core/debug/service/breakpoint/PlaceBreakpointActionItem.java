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
package ghidra.app.plugin.core.debug.service.breakpoint;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.program.model.address.*;

public class PlaceBreakpointActionItem implements BreakpointActionItem {
	private final TargetBreakpointSpecContainer container;
	private final Address address;
	private final long length;
	private final Set<TargetBreakpointKind> kinds;

	public PlaceBreakpointActionItem(TargetBreakpointSpecContainer container, Address address,
			long length, Collection<TargetBreakpointKind> kinds) {
		this.container = Objects.requireNonNull(container);
		this.address = Objects.requireNonNull(address);
		this.length = length;
		this.kinds = Set.copyOf(kinds);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof PlaceBreakpointActionItem)) {
			return false;
		}
		PlaceBreakpointActionItem that = (PlaceBreakpointActionItem) obj;
		if (this.container != that.container) {
			return false;
		}
		if (!this.address.equals(that.address)) {
			return false;
		}
		if (!Objects.equals(this.kinds, that.kinds)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(getClass(), container, address, kinds);
	}

	@Override
	public CompletableFuture<Void> execute() {
		AddressRange range;
		try {
			range = new AddressRangeImpl(address, length);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
		return container.placeBreakpoint(range, kinds);
	}
}
