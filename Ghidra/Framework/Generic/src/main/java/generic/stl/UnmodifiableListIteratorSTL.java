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

/** 
 * This wrapper class is used to detect cases where code is 
 * modifying iterators that shouldn't change.
 */
public class UnmodifiableListIteratorSTL<T> extends ListIterator<T> {

	public UnmodifiableListIteratorSTL( ListIterator<T> iterator ) {
		super( iterator.list, iterator.root, iterator.node );		
	}
	
	@Override
    public void assign( IteratorSTL<T> otherIterator ) {
		throw new UnsupportedOperationException( "Cannot modify this iterator!" );
	}

	@Override
    public IteratorSTL<T> decrement() {
		throw new UnsupportedOperationException( "Cannot modify this iterator!" );
	}

	@Override
    public IteratorSTL<T> decrement( int n ) {
		throw new UnsupportedOperationException( "Cannot modify this iterator!" );
	}

	public void delete() {
		throw new UnsupportedOperationException( "Cannot modify this iterator!" );
	}

	public void delete( int count ) {
		throw new UnsupportedOperationException( "Cannot modify this iterator!" );
	}

	@Override
    public IteratorSTL<T> increment() {
		throw new UnsupportedOperationException( "Cannot modify this iterator!" );
	}

	@Override
    public IteratorSTL<T> increment( int n ) {
		throw new UnsupportedOperationException( "Cannot modify this iterator!" );
	}

	@Override
    public void insert( T value ) {
		throw new UnsupportedOperationException( "Cannot modify this iterator!" );
	}

	@Override
    public void set( Object value ) {
		throw new UnsupportedOperationException( "Cannot modify this iterator!" );
	}

}
