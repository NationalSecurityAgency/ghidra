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
package ghidra.trace.model.target;

import java.util.Collection;
import java.util.stream.Stream;

import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.target.schema.TraceObjectSchema;

/**
 * A store of objects observed over time in a trace
 */
public interface TraceObjectManager {

	/**
	 * Get the trace to which the object manager belongs
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Creates the root object of the model, fixing its schema
	 * 
	 * <p>
	 * Note the schema cannot be changed once the root object is created. The only means to "change"
	 * the schema is to delete the root object (and thus the entire tree) then re-create the root
	 * object with the new schema.
	 * 
	 * @param schema the schema
	 * @return the new object
	 */
	TraceObjectValue createRootObject(TraceObjectSchema schema);

	/**
	 * Create (or get) an object with the given canonical path
	 * 
	 * @param path the object's canonical path
	 * @return the new object
	 */
	TraceObject createObject(KeyPath path);

	/**
	 * Get the schema of the root object
	 * 
	 * @return the schema
	 */
	TraceObjectSchema getRootSchema();

	/**
	 * Get the root object, if it has been created
	 * 
	 * @return the root object, or null
	 */
	TraceObject getRootObject();

	/**
	 * Get the object with the given database key, if it exists
	 * 
	 * @param key the desired object's key
	 * @return the object, or null
	 */
	TraceObject getObjectById(long key);

	/**
	 * Get objects in the database having the given canonical path
	 * 
	 * @param path the canonical path of the desired objects
	 * @return the collection of objects
	 */
	TraceObject getObjectByCanonicalPath(KeyPath path);

	/**
	 * Get objects in the database having the given path intersecting the given span
	 * 
	 * @param path the path of the desired objects
	 * @param span the span that desired objects' lifespans must intersect
	 * @return the iterable of objects
	 */
	Stream<? extends TraceObject> getObjectsByPath(Lifespan span,
			KeyPath path);

	/**
	 * Get value entries in the database matching the given predicates intersecting the given span
	 * 
	 * <p>
	 * While the manager does not maintain integrity wrt. child lifespans and that of their parents,
	 * nor even the connectivity of objects to their canonical parents, this search depends on that
	 * consistency. An object may not be discovered unless it is properly connected to the root
	 * object. Furthermore, it will not be discovered unless it and its ancestors' lifespans all
	 * intersect the given span.
	 * 
	 * @param span the span that desired objects' lifespans must intersect
	 * @param predicates predicates to match the desired objects
	 * @return an iterator over the matching objects
	 */
	Stream<? extends TraceObjectValPath> getValuePaths(Lifespan span,
			PathFilter predicates);

	/**
	 * Get all the objects in the database
	 * 
	 * @return the stream of all objects
	 */
	Stream<? extends TraceObject> getAllObjects();

	/**
	 * Get the number of objects in the database
	 * 
	 * @return the number of objects
	 */
	int getObjectCount();

	/**
	 * Get all the values (edges) in the database
	 * 
	 * @return the stream of all values
	 */
	Stream<? extends TraceObjectValue> getAllValues();

	/**
	 * Get all address-ranged values intersecting the given span and address range
	 * 
	 * @param span the span that desired values lifespans must intersect
	 * @param range the range that desired address-ranged values must intersect
	 * @param entryKey the entry key if a single one should be matched, or null for any
	 * @return the collection of values
	 */
	Collection<? extends TraceObjectValue> getValuesIntersecting(Lifespan span,
			AddressRange range, String entryKey);

	/**
	 * Get all address-ranged values intersecting the given span and address range
	 * 
	 * @param span the span that desired values lifespans must intersect
	 * @param range the range that desired address-ranged values must intersect
	 * @return the collection of values
	 */
	default Collection<? extends TraceObjectValue> getValuesIntersecting(Lifespan span,
			AddressRange range) {
		return getValuesIntersecting(span, range, null);
	}

	/**
	 * Get all interfaces of the given type in the database
	 * 
	 * @param <I> the type of the desired interface
	 * @param span the span that desired objects must intersect
	 * @param iface the class of the desired interface
	 * @return the collection of all instances of the given interface
	 */
	<I extends TraceObjectInterface> Stream<I> queryAllInterface(Lifespan span,
			Class<I> iface);

	/**
	 * For maintenance, remove all disconnected objects
	 * 
	 * <p>
	 * An object is disconnected if it is neither the child nor parent of any value for any span. In
	 * other words, it's unused.
	 */
	void cullDisconnectedObjects();

	/**
	 * Delete the <em>entire object model</em>, including the schema
	 * 
	 * <p>
	 * This is the only mechanism to modify the schema. This should almost never be necessary,
	 * because a connector should provide its immutable schema immediately. Nevertheless, the
	 * database permits schema modification, but requires that the entire model be replaced.
	 */
	void clear();
}
