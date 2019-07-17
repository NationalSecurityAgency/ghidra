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

/**  
 * An implementation of vertices for use in ghidra.util.graph.
 * 
 */
public class Vertex implements KeyedObject, Comparable<Vertex> {
	private final long key;
	private final Object referent;
	private static final KeyedObjectFactory vf = KeyedObjectFactory.getInstance();

	/**
	 * Creates a vertex tied to a referent object. The object the key refers
	 * to can be obtained from the vertex factory using the key of the vertex.
	 * If there is already a vertex having the same key as returned by
	 * KeyedObjectFactory.getInstance().getKeyForThisObject( Object o ), then a
	 * DuplicateKeyException is thrown and no vertex is created.
	 */
	public Vertex(Object referent)// throws DuplicateKeyException
	{
		this.key = vf.getNextAvailableKey();
		this.referent = referent;
	}

	/** 
	 * @return The key of this vertex. 
	 */
	public long key() {
		return this.key;
	}

	@Override
	public String toString() {
		if (referent != null) {
			return referent.toString();
		}
		return "Nexus";
	}

	/** 
	 * @return true iff and only if the given object is a Vertex with the same
	 * key.
	 */
	@Override
	public boolean equals(Object o) {
		if (o instanceof Vertex) {
			return key == ((Vertex) o).key();
		}
		return false;
	}

	/** 
	 * @return The Object this vertex refers to specified at creation time.
	 */
	public Object referent() {
		return this.referent;
	}

	/** 
	 * @see java.lang.Object#hashCode()
	 * Overides hashCode() to use the key of this Vertex.
	 */
	@Override
	public int hashCode() {
		return (int) this.key;
	}

	/** 
	 * Compares two vertices by keys. If the specified object o is not a Vertex a
	 * ClassCastException will be thrown.
	 */
	public int compareTo(Vertex v) {
		long difference = (v.key() - this.key);
		if (difference < 0) {
			return -1;
		}
		else if (difference == 0) {
			return 0;
		}
		else {
			return 1;
		}
	}

	/** 
	 * Return the name of this vertex. If the Vertex has a referent, the 
	 * referent's toString() method will be used to create the name. If
	 * the Vertex has a null referent, then the key will be used to determine
	 * the name.
	 */
	public String name() {
		if (referent != null) {
			return "Vertex:" + referent.toString().replace(' ', '_');
		}
		return "Vertex_" + Long.toHexString(key);
	}
}
