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
package ghidra.program.model.symbol;

import java.util.Iterator;

import util.CollectionUtils;

/**
 * Iterator that gives out MemReference objects.
 * 
 * @see CollectionUtils#asIterable
 */
public interface ReferenceIterator extends Iterator<Reference>, Iterable<Reference> {

	/**
	 * Returns whether there is a next memory reference in the iterator.
	 */
	@Override
	public boolean hasNext();

	/**
	 * Get the next memory reference.
	 * @return null if there is no next reference
	 */
	@Override
	public Reference next();
}
