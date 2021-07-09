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
package ghidra.program.model.listing;

import java.util.Iterator;

import util.CollectionUtils;

/**
 * Interface to define an iterator over over some set of  code units.
 * 
 * @see CollectionUtils#asIterable
 */
public interface CodeUnitIterator extends Iterator<CodeUnit>, Iterable<CodeUnit> {

	public static final CodeUnitIterator EMPTY_ITERATOR = new CodeUnitIterator() {

		@Override
		public boolean hasNext() {
			return false;
		}

		@Override
		public CodeUnit next() {
			return null;
		}

		@Override
		public Iterator<CodeUnit> iterator() {
			return this;
		}

	};

	/**
	 * Return true if there is a next CodeUnit.
	 */
	@Override
	public boolean hasNext();

	/**
	 * Get the next CodeUnit or null if no more CodeUnits.
	 * <P>NOTE: This deviates from the standard {@link Iterator} interface
	 * by returning null instead of throwing an exception.
	 */
	@Override
	public CodeUnit next();

}
