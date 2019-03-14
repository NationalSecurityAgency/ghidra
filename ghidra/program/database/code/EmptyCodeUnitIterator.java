/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.database.code;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;

import java.util.Iterator;

/**
 * CodeUnitIterator that represents an empty set of codeunits.
 */
public class EmptyCodeUnitIterator implements CodeUnitIterator {

	/**
	 * Constructs a new EmptyCodeUnitIterator
	 */
	public EmptyCodeUnitIterator() {
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#hasNext()
	 */
	@Override
	public boolean hasNext() {
		return false;
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#next()
	 */
	@Override
	public CodeUnit next() {
		return null;
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<CodeUnit> iterator() {
		return this;
	}
}
