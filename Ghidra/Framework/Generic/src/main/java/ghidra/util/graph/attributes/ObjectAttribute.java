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

import java.util.HashMap;
import java.util.Map;

import ghidra.util.graph.KeyIndexableSet;
import ghidra.util.graph.KeyedObject;

/** This class provides a storage mechanism for Object-valued information about
 *  the elements of a KeyIndexableSet, e.g. the vertices of a DirectedGraph.
 */
public class ObjectAttribute<T extends KeyedObject> extends Attribute<T> {
	//private Object[] values;
	private Map<Long, Object> values;
	private static String attributeType = AttributeManager.OBJECT_TYPE;

	/** Constructor.
	 * @param name The name used to identify this attribute.
	 * @param set The KeyIndexableSet whose elements can be assigned
	 * a value within this attribute.
	 */
	public ObjectAttribute(String name, KeyIndexableSet<T> set) {
		super(name, set);
		//this.values = new Object[set.capacity()];
		values = new HashMap<>();
	}

	/** Set the value of this attribute for the specified KeyedObject.
	 * @param o The KeyedObject that is assigned the value. Should
	 * be a member of the owningSet.
	 * @param value The value to associate with the specified KeyedObject.
	 * @return true if the value could be set. Return false if o is
	 * not a member of the owningSet.
	 */
	public boolean setValue(T o, Object value) {
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
	 * Return the value associated to the specified KeyedObject.
	 */
	public Object getValue(KeyedObject o) //throws NoValueException
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
//       while( iter.hasNext() )
//       {
//           o = iter.next();
//           Err.debug(this, "[ " + Long.toHexString(o.key()) + ", " + this.getValue(o) + "] \n");
//       }
//       Err.debug(this, "\n");
//  }

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
		Object v;
		if (values.containsKey(o.key())) {
			v = getValue(o);
			if (v != null) {
				return v.toString();
			}
		}
		return emptyString;
	}

	private static final String emptyString = "";
}
