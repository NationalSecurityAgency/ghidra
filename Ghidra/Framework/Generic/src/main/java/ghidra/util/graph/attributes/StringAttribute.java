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
package ghidra.util.graph.attributes;

import java.util.*;

import ghidra.util.graph.KeyIndexableSet;
import ghidra.util.graph.KeyedObject;

/** This class provides a storage mechanism for String-valued information about
*  the elements of a KeyIndexableSet, e.g. the vertices of a DirectedGraph.
*/
public class StringAttribute<T extends KeyedObject> extends Attribute<T> {
	//private String[] values;
	private Map<Long, String> values;
	private static String attributeType = AttributeManager.STRING_TYPE;

	/** Constructor.
	 * @param name The name used to identify this attribute.
	 * @param set The KeyIndexableSet whose elements can be assigned
	 * a value within this attribute.
	 */
	public StringAttribute(String name, KeyIndexableSet<T> set) {
		super(name, set);
		this.values = new HashMap<>();
	}

	/** Set the value of this attribute for the specified KeyedObject.
	 * @param o The KeyedObject that is assigned the value. Should
	 * be a member of the owningSet.
	 * @param value The value to associate with the specified KeyedObject.
	 * @return true if the value could be set. Return false if o is
	 * not a member of the owningSet.
	 */
	public boolean setValue(T o, String value) {
		if (value == null) {
			return false;
		}
		if (owningSet().contains(o)) {
			//values[ owningSet().index( o ) ] = value;
			values.put(o.key(), value);
			update();
			return true;
		}
		return false;
	}

	/**
	 * Return the value associated to the specied KeyedObject.
	 */
	public String getValue(KeyedObject o) //throws NoValueException
	{
		//return values[ owningSet().index( o ) ];
		return values.get(o.key());
	}

//	/** Debug printing. */
//  private void reportValues()
//  {
//       Err.debug(this,  "Attribute: " + name() + "\n" );
//       GraphIterator iter = this.owningSet().iterator();
//       KeyedObject o;
//        	while( iter.hasNext() )
//       	{
//           o = iter.next();
//           Err.debug(this, "[ " + Long.toHexString(o.key()) + ", " + this.getValue(o) + "] \n");
//       	}
//       Err.debug(this, "\n");
//  }

	/** Returns the elements of the owningSet sorted by their
	 * values of this Attribute. 
	 */
	public KeyedObject[] toSortedArray() {
		KeyedObject[] keyedObjects = this.owningSet().toArray();
		Arrays.sort(keyedObjects, new StringComparator());
		return keyedObjects;
	}

	/** Sorts the array of keyedObjects by their values of this 
	 * Attribute.
	 */
	public KeyedObject[] toSortedArray(KeyedObject[] keyedObjects) {
		KeyedObject[] clone = keyedObjects.clone();
		Arrays.sort(clone, new StringComparator());
		return clone;
	}

	/** This class is a comparator (see java.util.Comparator) for
	 * KeyedObjects having a StringAttribute. Keyed Objects are first
	 * compared by the value of the attribute. Ties are broken by
	 * considering the keys of the KeyedObjects.
	 */
	class StringComparator implements Comparator<KeyedObject> {
		@Override
		public int compare(KeyedObject object1, KeyedObject object2) {
			KeyedObject ko1 = object1;
			KeyedObject ko2 = object2;
			int returnValue = 0;
			String value1 = null;
			String value2 = null;
			value1 = getValue(ko1); //}catch( NoValueException exc ){value1 = null;}          	
			value2 = getValue(ko2); //} catch( NoValueException exc){value2 = null;}          	

			if (value1 != null) {
				if (value2 != null) {
					returnValue = value1.compareTo(value2);
					if (returnValue != 0) {
						return returnValue;
					}
					if ((ko1.key() - ko2.key()) < 0) {
						return -1;
					}
					else if ((ko1.key() - ko2.key()) > 0) {
						return +1;
					}
					else {
						return 0;
					}
				}
				//ko1 is ok, ko2 fails.
				return -1;
			}
			if (value2 != null) {
				return 1; //ko2 is ok so it precedes ko1
			}
			if ((ko1.key() - ko2.key()) < 0) {
				return -1;
			}
			else if ((ko1.key() - ko2.key()) > 0) {
				return +1;
			}
			else {
				return 0;
			}
		}
	}

	/** Return the type of Attribute, i.e. what kind of values does
	 * this attribute hold. "Long", "Object", "Double" are examples.
	 */
	@Override
	public String attributeType() {
		return attributeType;
	}

	/** Removes all assigned values of this attribute. */
	@Override
	public void clear() {
		values.clear();
	}

	/** Return the attribute of the specified KeyedObject as a String.
	 */
	@Override
	public String getValueAsString(KeyedObject o) {
		return getValue(o);
	}

}
