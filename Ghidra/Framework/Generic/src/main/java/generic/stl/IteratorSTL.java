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
package generic.stl;


public interface IteratorSTL<T> {
	
	/**
	 * Returns the current value of the iterator.
	 * @return the current value of the iterator.
	 * @throws IndexOutOfBoundsException if the iterator is positioned before the first value or
	 * after the last value.
	 */
	T get();
	
	/**
	 * Sets the current value of the iterator to the given value.
	 * @param value the value to set at the iterator position
	 * @throws IndexOutOfBoundsException if the iterator is positioned befor the first value or
	 * after the last value.
	 */
	void set(T value);
	
	/**
	 * Advances the iterator to the next position.
	 * @return a reference to the iterator itself
	 * @throws IndexOutOfBoundsException if the the iterator is already past the last element.
	 */
	IteratorSTL<T> increment();

	/**
	 * Advances the iterator n positions.
	 * @return a reference to the iterator itself
	 * @throws IndexOutOfBoundsException if the n value pushes past the end of the collection.
	 */
	IteratorSTL<T> increment(int n);
	
	
	/**
	 * Devance the iterator to the previous position.  This method is only supported in 
	 * bidirectional iterators.
	 * @return a reference to the iterator itself
	 */
	IteratorSTL<T> decrement();

	/**
	 * Devances the iterator n positions.
	 * @return a reference to the iterator itself
	 * @throws IndexOutOfBoundsException if the n value pushes past the beginning of the collection
	 */
	IteratorSTL<T> decrement(int n);

	/**
	 * Returns true if the iterator is positioned on the first first element of the collection.  If the
	 * collection is empty, this will always return false.
	 * @return true if the iterator is positioned on the first element of the collection.
	 */
	boolean isBegin();
	
	/**
	 * Returns true if the iterator is positioned past the last element of the collection.  If the
	 * collection is empty, this will always return true.
	 * @return true if the iterator is positioned past the last element of the collection.
	 */
	boolean isEnd();

	/**
	 * Inserts the given value at the current position (the current value will be pushed to the next value).
	 * The iterator will be positioned on the new value.
	 * @param value the value to insert into the collection.
	 * @throws IndexOutOfBoundsException if the iterator is positioned before the first item.
	 */
	void insert(T value);

	/**
	 * Creates a copy of this iterator.
	 * @return a copy of this iterator.
	 */
	IteratorSTL<T> copy();

	/**
	 * 'Assigns' this iterator to be equivalent to the given iterator.  This is equivalent to
	 * C++'s '=' overloading mechanism
	 * @param otherIterator The iterator to copy
	 */
	void assign( IteratorSTL<T> otherIterator );
}
