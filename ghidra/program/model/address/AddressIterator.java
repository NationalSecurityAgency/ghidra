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
package ghidra.program.model.address;

import java.util.Iterator;

import util.CollectionUtils;

/**
 * <p>AddressIterator is used to iterate over some set of addresses.
 *
 * <p>Note: The next and previous methods return <i>Address</i>s.
 * </p>
 *
 * @version 2000-02-16
 * @see CollectionUtils#asIterable
 */

public interface AddressIterator extends Iterator<Address>, Iterable<Address> {
	/**
	 * Get the next address.
	 * 
	 * @return the next address in the iteration.
	 */
	@Override
	public Address next();

	/**
	 * Checks if there is a next address in the iteration.
	 * 
	 * @return true if there is a next address.
	 */
	@Override
	public boolean hasNext();

}
