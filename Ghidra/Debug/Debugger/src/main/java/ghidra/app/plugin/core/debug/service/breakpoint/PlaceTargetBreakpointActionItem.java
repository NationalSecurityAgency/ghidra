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

public record PlaceTargetBreakpointActionItem(TargetBreakpointSpecContainer container,
		Address address, long length, Set<TargetBreakpointKind> kinds)
		implements BreakpointActionItem {

	public PlaceTargetBreakpointActionItem(TargetBreakpointSpecContainer container, Address address,
			long length, Set<TargetBreakpointKind> kinds) {
		this.container = container;
		this.address = address;
		this.length = length;
		this.kinds = Set.copyOf(kinds);
	}

	@Override
	public CompletableFuture<Void> execute() {
		return container.placeBreakpoint(range(address, length), kinds);
	}
}
