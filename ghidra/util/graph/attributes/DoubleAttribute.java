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
package ghidra.util.graph.attributes;

import ghidra.util.datastruct.LongDoubleHashtable;
import ghidra.util.exception.NoValueException;
import ghidra.util.graph.KeyIndexableSet;
import ghidra.util.graph.KeyedObject;

import java.util.Arrays;
import java.util.Comparator;

/** This class provides a storage mechanism for double-valued information about
 *  the elements of a KeyIndexableSet, e.g. the vertices of a DirectedGraph.
 */
public class DoubleAttribute<T extends KeyedObject> extends Attribute<T> {
	//private double [] values;
	private LongDoubleHashtable values;
	private static String attributeType = AttributeManager.DOUBLE_TYPE;

	/** Constructor.
	 * @param name The name used to identify this attribute.
	 * @param set The KeyIndexableSet whose elements can be assigned
	 * a value within this attribute.
	 */
	public DoubleAttribute(String name, KeyIndexableSet<T> set) {
		super(name, set);
		//this.values = new double[set.capacity()];
		values = new LongDoubleHashtable();
	}

	/** Set the value of this attribute for the specified KeyedObject.
	 * @param o The KeyedObject that is assigned the value. Should
	 * be a member of the owningSet.
	 * @param value The value to associate with the specified KeyedObject.
	 * @return true if the value could be set. Return false if o is
	 * not a member of the owningSet.
	 */
	public boolean setValue(T o, double value) {
		if (owningSet().contains(o)) {
			//values[ owningSet().index( o ) ] = value;
			values.put(o.key(), value);
			update();
			return true;
		}
		return false;
	}

	/** Return the value associated to the specified KeyedObject.
	 * @throws NoValueException if the value has not been set or 
	 * the KeyedObject does not belong to the owningSet.
	 */
	public double getValue(KeyedObject o) throws NoValueException {
		//return values[ owningSet().index( o ) ];
		return values.get(o.key());
	}

//  /** Debug printing */
//  private void reportValues()
//  {
//       Err.debug(this,  "Attribute: " +  this.name() + "\n" );
//       GraphIterator iter = owningSet().iterator();
//       KeyedObject o;
//       try
//       {
//         while( iter.hasNext() )
//         {
//           o = iter.next();
//           Err.debug(this, "[ " + Long.toHexString(o.key()) + ", " + this.getValue(o) + "] \n");
//         }
//         Err.debug(this, "\n");
//       }
//       catch( ghidra.util.exception.NoValueException exc )
//       {
//          Err.error(this, null, "Error", "Unexpected Exception: " + e.getMessage(), e);
//       }
//  }

	/** Returns the elements of the owningSet sorted by their
	 * values of this Attribute. 
	 */
	public KeyedObject[] toSortedArray() {
		KeyedObject[] keyedObjects = this.owningSet().toArray();
		Arrays.sort(keyedObjects, new DoubleComparator());
		return keyedObjects;
	}

	/** Sorts the array of keyedObjects by their values of this 
	 * Attribute.
	 */
	public KeyedObject[] toSortedArray(KeyedObject[] keyedObjects) {
		KeyedObject[] clone = keyedObjects.clone();
		Arrays.sort(clone, new DoubleComparator());
		return clone;
	}

	/** This class is a comparator (see java.util.Comparator) for
	 * KeyedObjects having a DoubleAttribute. Keyed Objects are first
	 * compared by the value of the attribute. Ties are broken by
	 * considering the keys of the KeyedObjects.
	 */
	class DoubleComparator implements Comparator<KeyedObject> {
		/** Compares two Objects. See java.util.Comparator */
		@Override
		public int compare(KeyedObject object1, KeyedObject object2) {
			KeyedObject ko1 = object1;
			KeyedObject ko2 = object2;
			double value1 = 0;
			double value2 = 0;
			try {
				value1 = getValue(ko1);
				try {
					value2 = getValue(ko2);
					if ((value1 - value2) < 0) {
						return -1;
					}
					else if ((value1 - value2) > 0) {
						return +1;
					}
					else {
						if ((ko1.key() - ko2.key()) < 0) {
							return -1;
						}
						else if ((ko1.key() - ko2.key()) > 0) {
							return +1;
						}
						else
							return 0;
					}
				}
				catch (NoValueException exc2) {
					//ko1 is ok, ko2 fails.
					return -1;
				}
			}
			catch (ghidra.util.exception.NoValueException exc) {
				try {
					value2 = getValue(ko2);
					return 1; //ko2 is ok so it preceeds ko1
				}
				catch (ghidra.util.exception.NoValueException exc2) {
					if ((ko1.key() - ko2.key()) < 0) {
						return -1;
					}
					else if ((ko1.key() - ko2.key()) > 0) {
						return +1;
					}
					else
						return 0;
				}
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
		values.removeAll();
	}

	/** Return the attribute of the specified KeyedObject as a String.
	 */
	@Override
	public String getValueAsString(KeyedObject o) {
		try {
			return Double.toString(getValue(o));
		}
		catch (ghidra.util.exception.NoValueException exc) {
			return "0.0";
		}
	}
}
