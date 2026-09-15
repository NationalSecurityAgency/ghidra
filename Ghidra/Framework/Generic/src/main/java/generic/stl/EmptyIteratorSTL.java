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
package generic.stl;


public class EmptyIteratorSTL<T> implements IteratorSTL<T> {

	@Override
	public IteratorSTL<T> copy() {
		return this;
	}

	public void delete() {
		throw new UnsupportedOperationException();
	}

	public void delete( int count ) {
		throw new UnsupportedOperationException();
	}

	@Override
	public T get() {
		return null;
	}

	@Override
	public IteratorSTL<T> increment() {
		throw new IndexOutOfBoundsException();
	}

	@Override
	public IteratorSTL<T> decrement() {
		throw new IndexOutOfBoundsException();
	}
	
	@Override
	public void insert( T value ) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isBegin() {
		return true;
	}

	@Override
	public boolean isEnd() {
		return true;
	}

	@Override
	public void set( T value ) {
		throw new UnsupportedOperationException();
	}

	@Override
	public IteratorSTL<T> decrement( int n ) {
		throw new UnsupportedOperationException();
	}

	@Override
	public IteratorSTL<T> increment( int n ) {
		throw new UnsupportedOperationException();
	}

	public boolean isRBegin() {
		return true;
	}

	public boolean isREnd() {
		return true;
	}
	
	@Override
	public void assign( IteratorSTL<T> otherIterator ) {
		throw new UnsupportedOperationException();
	}
}
