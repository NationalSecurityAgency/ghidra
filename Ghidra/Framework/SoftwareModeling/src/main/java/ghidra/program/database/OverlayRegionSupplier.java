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
package ghidra.program.database;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.OverlayAddressSpace;

/**
 * {@link OverlayRegionSupplier} provides a callback mechanism which allows a
 * {@link ProgramOverlayAddressSpace} to identify defined memory regions within its
 * space so that it may properly implement the {@link OverlayAddressSpace#contains(long)}
 * method.
 */
public interface OverlayRegionSupplier {

	/**
	 * Get the set of memory address defined within the specified overlay space.
	 * @param overlaySpace overlay address space
	 * @return set of memory address defined within the specified overlay space or null
	 */
	AddressSetView getOverlayAddressSet(OverlayAddressSpace overlaySpace);

}
