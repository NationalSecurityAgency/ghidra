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
package ghidra.util.graph;


/** Interface for sets of graph objects which have keys such as vertices
 * and edges.
 * 
 * 
 */
public interface KeyIndexableSet<T extends KeyedObject> {
	/** The modification number is a counter for the number of changes
	 * the KeyIndexableSet has undergone since its creation. 
	 */
  public long getModificationNumber();
  
  /** Returns the number of KeyedObjects in this KeyIndexableSet */
  public int size();
  
  /** Returns the number of KeyedObjects this KeyIndexableSet can
   * hold without growing. 
   */
  public int capacity();
  
  /** Adds a KeyedObject to this KeyIndexableSet. The set will increase
   * in capacity if needed.
   * @return true if the KeyedObject was successfully added. Returns false
   * if the KeyedObject is null or already in the KeyIndexableSet or addition
   * fails for some other reason.
   */
  public boolean add( T o );
  
  /** Remove a KeyedObject from this KeyIndexableSet. 
   * @return true if the KeyedObject was sucessfully removed. Returns false
   * if the KeyedObject was not in the KeyIndexablrSet.
   */
  public boolean remove( T o );
  
  /** Returns true if this KeyIndexableSet contains the specified KeyedObject.
   */
  public boolean contains( T o );
  
  /** Returns an iterator for this KeyIndexableSet which uses the
   * hasNext()/next() style. See GraphIterator. */
  public GraphIterator<T> iterator();

	/** Returns the elements of this KeyIndexableSet as an array of
	 * KeyedObjects.
	 */
  public T[] toArray();
  
  /** Returns the KeyedObject with the specified key in this KeyIndexableSet.
   * Returns null if the Set contains no object with that key.
   */
  public T getKeyedObject( long key);

}
