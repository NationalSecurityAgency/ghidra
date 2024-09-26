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
package ghidra.features.base.memsearch.bytesource;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * Interface to specify a named region within a byte source (Program) that users can select to
 * specify {@link AddressSetView}s that can be searched.
 */
public interface SearchRegion {

	/**
	 * The name of the region.
	 * @return the name of the region
	 */
	public String getName();

	/**
	 * Returns a description of the region.
	 * @return a description of the region
	 */
	public String getDescription();

	/**
	 * Returns the set of addresses from a specific program that is associated with this region.
	 * @param program the program that determines the specific addresses for a named region
	 * @return the set of addresses for this region as applied to the given program
	 */
	public AddressSetView getAddresses(Program program);

	/**
	 * Returns true if this region should be included in the default selection of which regions to
	 * search.
	 * @return true if this region should be selected by default
	 */
	public boolean isDefault();
}
