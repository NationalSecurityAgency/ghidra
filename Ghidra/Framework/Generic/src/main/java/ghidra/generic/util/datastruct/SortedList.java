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
package ghidra.generic.util.datastruct;

import java.util.List;

/**
 * An interface for sorted lists
 *
 * <p>
 * This might be better described as a NavigableMultiset; however, I wish for the elements to be
 * retrievable by index, though insertion and mutation is not permitted by index. This implies that
 * though unordered, the underlying implementation has sorted the elements in some way and wishes to
 * expose that ordering to its clients.
 *
 * @param <E> the type of elements in this list
 */
public interface SortedList<E> extends List<E> {
	/**
	 * Returns the greatest index in this list whose element is strictly less than the specified
	 * element
	 * 
	 * @param element the element to search for
	 * @return the index of the found element, or -1
	 */
	int lowerIndex(E element);

	/**
	 * Returns the greatest index in this list whose element is less than or equal to the specified
	 * element
	 * 
	 * <p>
	 * If multiples of the specified element exist, this returns the least index of that element.
	 * 
	 * @param element the element to search for
	 * @return the index of the found element, or -1
	 */
	int floorIndex(E element);

	/**
	 * Returns the least index in this list whose element is greater than or equal to the specified
	 * element
	 * 
	 * <p>
	 * If multiples of the specified element exist, this returns the greatest index of that element.
	 * 
	 * @param element the element to search for
	 * @return the index of the found element, or -1
	 */
	int ceilingIndex(E element);

	/**
	 * Returns the least index in this list whose element is strictly greater the specified element
	 * 
	 * @param element the element to search for
	 * @return the index of the found element, or -1
	 */
	int higherIndex(E element);
}
