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

import ghidra.util.graph.KeyIndexableSet;
import ghidra.util.graph.KeyedObject;

/** Base class for attributes -- int, double, or String values -- which can
 *  be assigned to the members of a KeyIndexableSet, e.g. the vertices or
 *  edges of a DirectedGraph. The attributes do not track changes in the owning
 *  set, but you can check if the owning set has been modified since creation
 *  time. It is possible to create an attribute on the vertex set and then
 *  remove the vertex from the graph. An attempt to get the value associated
 *  with that vertex will cause a NoValueException to be thrown.
 *
 *
 */
public abstract class Attribute<T extends KeyedObject> {
	private final KeyIndexableSet<T> owningSet;
	private final String attributeName;
	private long modificationNumber;
	private long backingSetModificationNumber;

	/** Constructor
	 * 
	 * @param name name of the attribute
	 * @param set set whose members may have attribute values defined
	 */
	public Attribute(String name, KeyIndexableSet<T> set) {
		this.owningSet = set;
		this.attributeName = name;
		this.modificationNumber = 0;
		this.backingSetModificationNumber = set.getModificationNumber();
		//this.values = new double[set.capacity()];
	}

	/** Increase the modificationNumber. */
	void update() {
		modificationNumber++;
	}

	/** Returns true iff the set attributes are defined for has not changed 
	 * since the set was created. */
	boolean owningSetIsUnmodified() {
		if (this.backingSetModificationNumber == this.owningSet.getModificationNumber()) {
			return true;
		}
		return false;
	}

	/** Return the current value of the modificationNumber which counts
	 * the number of changes this Attribute has undergone.
	 */
	public long getModificationNumber() {
		return modificationNumber;
	}

	/** Return the name of this Attribute. */
	public String name() {
		return this.attributeName;
	}

	/** Return the KeyIndexableSet, typically a VertexSet or EdgeSet, that
	 * this attribute is defined for. An attribute value can only be set
	 * for a KeyedObject if it is a member of the owningSet.
	 */
	public KeyIndexableSet<T> owningSet() {
		return this.owningSet;
	}

	/** Return the type of Attribute, i.e. what kind of values does
	 * this attribute hold. "Long", "Object", "Double" are examples.
	 */
	abstract public String attributeType();

	/** Return the attribute of the specified KeyedObject as a String.
	 */
	abstract public String getValueAsString(KeyedObject o);

	/** Undefine all values set for this attribute. */
	abstract public void clear();

}
