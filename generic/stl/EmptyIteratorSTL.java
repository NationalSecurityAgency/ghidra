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


public class EmptyIteratorSTL<T> implements IteratorSTL<T> {

	public IteratorSTL<T> copy() {
		return this;
	}

	public void delete() {
		throw new UnsupportedOperationException();
	}

	public void delete( int count ) {
		throw new UnsupportedOperationException();
	}

	public T get() {
		return null;
	}

	public IteratorSTL<T> increment() {
		throw new IndexOutOfBoundsException();
	}

	public IteratorSTL<T> decrement() {
		throw new IndexOutOfBoundsException();
	}
	
	public void insert( T value ) {
		throw new UnsupportedOperationException();
	}

	public boolean isBegin() {
		return true;
	}

	public boolean isEnd() {
		return true;
	}

	public void set( T value ) {
		throw new UnsupportedOperationException();
	}

	public IteratorSTL<T> decrement( int n ) {
		throw new UnsupportedOperationException();
	}

	public IteratorSTL<T> increment( int n ) {
		throw new UnsupportedOperationException();
	}

	public boolean isRBegin() {
		return true;
	}

	public boolean isREnd() {
		return true;
	}
	
	public void assign( IteratorSTL<T> otherIterator ) {
		throw new UnsupportedOperationException();
	}
}
