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

import java.util.List;

import ghidra.program.model.address.Address;

/**
 * Interface for reading bytes from a program. This provides a level of indirection for reading the
 * bytes of a program so that the provider of the bytes can possibly do more than just reading the
 * bytes from the static program. For example, a debugger would have the opportunity to refresh the
 * bytes first.
 * <P>
 * This interface also provides methods for determining what regions of memory can be queried and
 * what addresses sets are associated with those regions. This would allow client to present choices
 * about what areas of memory they are interested in AND are valid to be examined.
 */
public interface AddressableByteSource {

	/**
	 * Retrieves the byte values for an address range.
	 * 
	 * @param address The address of the first byte in the range
	 * @param bytes the byte array to store the retrieved byte values
	 * @param length the number of bytes to retrieve
	 * @return the number of bytes actually retrieved
	 */
	public int getBytes(Address address, byte[] bytes, int length);

	/**
	 * Returns a list of memory regions where each region has an associated address set of valid
	 * addresses that can be read.
	 * 
	 * @return a list of readable regions
	 */
	public List<SearchRegion> getSearchableRegions();

	/**
	 * Invalidates any caching of byte values. This intended to provide a hint in debugging scenario
	 * that we are about to issue a sequence of byte value requests where we are re-acquiring
	 * previous requested byte values to look for changes.
	 */
	public void invalidate();

}
