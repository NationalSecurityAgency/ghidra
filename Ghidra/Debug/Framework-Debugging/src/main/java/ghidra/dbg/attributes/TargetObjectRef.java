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
package ghidra.dbg.attributes;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import ghidra.async.AsyncFence;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.error.DebuggerModelTypeException;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.PathComparator;
import ghidra.dbg.util.PathUtils.TargetObjectKeyComparator;

/**
 * A reference (or stub) to a target object
 * 
 * <p>
 * These can be constructed and manipulated client-side, without querying the agent. However, a
 * reference is not guaranteed to refer to a valid object.
 * 
 * <p>
 * Note that it is OK for more than one {@link TargetObjectRef} to refer to the same path. These
 * objects must override {@link #equals(Object)} and {@link #hashCode()}.
 * 
 * @deprecated Use {@link TargetObjectPath} for model-bound path manipulation instead. Models should
 *             not longer return nor push stubs, but actual objects.
 */
@Deprecated
public interface TargetObjectRef extends Comparable<TargetObjectRef> {

	/**
	 * Check for target object equality
	 * 
	 * <p>
	 * Because interfaces cannot provide default implementations of {@link #equals(Object)}, this
	 * methods provides a means of quickly implementing it within a class. Because everything that
	 * constitutes target object equality is contained in the reference (model, path), there should
	 * never be a need to perform more comparison than is provided here.
	 * 
	 * @param obj the other object
	 * @return true if they are equal
	 */
	default boolean doEquals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TargetObjectRef)) {
			return false;
		}
		TargetObjectRef that = (TargetObjectRef) obj;
		return this.getModel() == that.getModel() &&
			Objects.equals(this.getPath(), that.getPath());
	}

	/**
	 * Pre-compute this object's hash code
	 * 
	 * <p>
	 * Because interfaces cannot provide default implementations of {@link #hashCode()}, this method
	 * provides a means of quickly implementing it within a class. Because everything that
	 * constitutes target object equality is <em>immutable</em> and contained in the reference
	 * (model, path), this hash should be pre-computed a construction. There should never be a need
	 * to incorporate more fields into the hash than is incorporated here.
	 * 
	 * @return the hash
	 */
	default int computeHashCode() {
		return System.identityHashCode(getModel()) * 31 + Objects.hash(getPath().toArray());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * A friendly reminder to override
	 * 
	 * @see #doEquals(Object)
	 */
	@Override
	boolean equals(Object obj);

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * A friendly reminder to override
	 * 
	 * @see #computeHashCode()
	 */
	@Override
	int hashCode();

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Along with {@link #doEquals(Object)} and {@link #computeHashCode()}, these obey the Rule of
	 * Three, comparing first the objects' models (by name, then identity), then their paths. Like
	 * the other methods, this incorporates everything that constitutes a unique target object.
	 * There should never be a need to override or otherwise extend this.
	 */
	@Override
	default int compareTo(TargetObjectRef that) {
		if (this == that) {
			return 0;
		}
		DebuggerObjectModel thisModel = this.getModel();
		DebuggerObjectModel thatModel = that.getModel();
		if (thisModel != thatModel) {
			if (thisModel == null) {
				return -1;
			}
			if (thatModel == null) {
				return 1;
			}
			int result = thisModel.toString().compareTo(thatModel.toString());
			if (result == 0) {
				return Integer.compare(
					System.identityHashCode(thisModel),
					System.identityHashCode(thatModel));
			}
			return result;
		}
		return PathComparator.KEYED.compare(this.getPath(), that.getPath());
	}

	/**
	 * Get the actual object
	 * 
	 * @return a future which completes with the object
	 * @deprecated Just cast straight to {@link TargetObject}. There should never exist a
	 *             {@link TargetObjectRef} that is not already a {@link TargetObject}, anymore.
	 */
	@Deprecated
	public default CompletableFuture<? extends TargetObject> fetch() {
		return getModel().fetchModelObject(getPath());
	}

	/**
	 * Cast the reference (or object) to the requested interface
	 * 
	 * <p>
	 * Upon retrieval, or if the object is already available locally (by implementation or by
	 * proxy), the object is checked for the requested interface and cast appropriately.
	 * 
	 * @param cls the class for the required interface. Use {@code tclass} to satisfy the recursive
	 *            type parameter.
	 * @return the reference (or object) conforming to the required type
	 * @throws DebuggerModelTypeException if the object is available locally but does not support
	 *             the desired interface
	 */
	public default <T extends TypedTargetObject<T>> TypedTargetObjectRef<T> as(Class<T> cls) {
		return TypedTargetObjectRef.casting(cls, this);
	}

	/**
	 * Get the model to which this object belongs
	 * 
	 * @return the model
	 */
	public DebuggerObjectModel getModel();

	/**
	 * Get the path (i.e., list of names from root to this object).
	 * 
	 * <p>
	 * Every object must have a unique path. Parts of the path which are indices, i.e., which
	 * navigate the elements, are enclosed in brackets @{code []}. Parts which navigate attributes
	 * are simply the attribute name.
	 * 
	 * <p>
	 * More than just a location, the path provides a hint to the object's scope of applicability.
	 * For example, a {@link TargetMemory} attribute of a process is assumed accessible to every
	 * thread of that process, since those threads are descendants.
	 * 
	 * @implNote it would be wise to cache the result of this computation. If the object has a
	 *           strict location, then the implementation should just return it directly.
	 * 
	 * @return the canonical path of the object
	 */
	public List<String> getPath();

	/**
	 * Get the path joined by the given separator
	 * 
	 * <p>
	 * Note that no check is applied to guarantee the path separator does not appear in an element
	 * name.
	 * 
	 * @see #getPath()
	 * @param sep the path separator
	 * @return the joined path
	 * @deprecated use {@link PathUtils#toString()} instead
	 */
	@Deprecated
	public default String getJoinedPath(String sep) {
		return StringUtils.join(getPath(), sep);
	}

	/**
	 * Get the key for this object
	 * 
	 * <p>
	 * The object's key should be that assigned by the actual debugger, if applicable. If this is an
	 * element, the key should include the brackets {@code []}. If it is an attribute, it should
	 * simply be the name.
	 * 
	 * @return the key, or {@code null} if this is the root
	 */
	public default String getName() {
		return PathUtils.getKey(getPath());
	}

	/**
	 * Get the index for this object
	 * 
	 * @return they index, or {@code null} if this is the root
	 * @throws IllegalArgumentException if this object is not an element of its parent
	 */
	public default String getIndex() {
		return PathUtils.getIndex(getPath());
	}

	/**
	 * Check if this is the root target debug object
	 * 
	 * @return true if root, false otherwise
	 */
	public default boolean isRoot() {
		return getPath().isEmpty();
	}

	/**
	 * Get a reference to the parent of this reference
	 * 
	 * @return the parent reference, or {@code null} if this refers to the root
	 */
	public default TargetObjectRef getParent() {
		List<String> parentPath = PathUtils.parent(getPath());
		if (parentPath == null) {
			return null;
		}
		return getModel().createRef(parentPath);
	}

	/**
	 * Fetch all the attributes of this object
	 * 
	 * <p>
	 * Attributes are usually keyed by a string, and the types are typically not uniform. Some
	 * attributes are primitives, while others are other target objects.
	 * 
	 * <p>
	 * Note, for objects, {@link TargetObject#getCachedAttributes()} should be sufficient to get an
	 * up-to-date view of the attributes, since the model should be pushing attribute updates to the
	 * object automatically. {@code fetchAttributes} should only be invoked on references, or in the
	 * rare case the client needs to ensure the attributes are fresh.
	 * 
	 * @param refresh true to invalidate all caches involved in handling this request
	 * @return a future which completes with a name-value map of attributes
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchAttributes(boolean refresh) {
		return getModel().fetchObjectAttributes(getPath(), refresh);
	}

	/**
	 * Fetch all attributes of this object, without refreshing
	 * 
	 * @see #fetchAttributes(boolean)
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchAttributes() {
		return fetchAttributes(false);
	}

	/**
	 * Fetch an attribute by name
	 * 
	 * @see #fetchAttributes()
	 * @see PathUtils#isInvocation(String)
	 * @implNote for attributes representing method invocations, the name will not likely be in the
	 *           map given by {@link #fetchAttributes()}. It will be generated upon request. The
	 *           implementation should cache the generated attribute until the attribute cache is
	 *           refreshed. TODO: Even if the method is likely to return a different value on its
	 *           next invocation? Yes, I think so. The user should manually refresh in those cases.
	 * @return a future which completes with the attribute or with {@code null} if the attribute
	 *         does not exist
	 */
	public default CompletableFuture<?> fetchAttribute(String name) {
		if (!PathUtils.isInvocation(name)) {
			return fetchAttributes().thenApply(m -> m.get(name));
		}
		// TODO: Make a type for the invocation and parse arguments better?
		Entry<String, String> invocation = PathUtils.parseInvocation(name);
		return fetchAttribute(invocation.getKey()).thenCompose(obj -> {
			if (!(obj instanceof TargetMethod<?>)) {
				throw new DebuggerModelTypeException(invocation.getKey() + " is not a method");
			}
			TargetMethod<?> method = (TargetMethod<?>) obj;
			// Just blindly invoke and let it sort it out
			return method.invoke(Map.of("arg", invocation.getValue()));
		});
	}

	/**
	 * Fetch all the elements of this object
	 * 
	 * <p>
	 * Elements are usually keyed numerically, but allows strings for flexibility. They values are
	 * target objects, uniform in type, and should generally share the same attributes. The keys
	 * must not contain the brackets {@code []}. Implementations should ensure that the elements are
	 * presented in order by key -- not necessarily lexicographically. To ensure clients can easily
	 * maintain correct sorting, the recommendation is to present the keys as follows: Keys should
	 * be the numeric value encoded as strings in base 10 or base 16 as appropriate, using the least
	 * number of digits needed. While rarely used, a comma-separated list of indices may be
	 * presented. Key comparators should separate the indices, attempt to convert each to a number,
	 * and then sort using the left-most indices first. Indices which cannot be converted to numbers
	 * should be sorted lexicographically. It is the implementation's responsibility to ensure all
	 * indices follow a consistent scheme.
	 * 
	 * @param refresh true to invalidate all caches involved in handling this request
	 * @return a future which completes with a index-value map of elements
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchElements(
			boolean refresh) {
		return getModel().fetchObjectElements(getPath(), refresh);
	}

	/**
	 * Fetch all elements of this object, without refreshing
	 * 
	 * @see #fetchElements(boolean)
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchElements() {
		return fetchElements(false);
	}

	/**
	 * Fetch all children (elements and attributes) of this object
	 * 
	 * <p>
	 * Note that keys for element indices here must contain the brackets {@code []} to distinguish
	 * them from attribute names.
	 * 
	 * @see #fetchElements()
	 * @see #fetchAttributes()
	 * 
	 * @param refresh true to invalidate all caches involved in handling this request
	 * @return a future which completes with a name-value map of children
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchChildren(boolean refresh) {
		AsyncFence fence = new AsyncFence();
		Map<String, Object> children = new TreeMap<>(TargetObjectKeyComparator.CHILD);
		fence.include(fetchElements(refresh).thenAccept(elements -> {
			for (Map.Entry<String, ?> ent : elements.entrySet()) {
				children.put(PathUtils.makeKey(ent.getKey()), ent.getValue());
			}
		}));
		fence.include(fetchAttributes(refresh).thenAccept(children::putAll));
		return fence.ready().thenApply(__ -> children);
	}

	/**
	 * Fetch all children of this object, without refreshing
	 * 
	 * @see #fetchChildren(boolean)
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchChildren() {
		return fetchChildren(false);
	}

	/**
	 * Fetch an element by its index
	 * 
	 * @return a future which completes with the element or with {@code null} if it does not exist
	 */
	public default CompletableFuture<? extends TargetObject> fetchElement(String index) {
		return getModel().fetchModelObject(PathUtils.index(getPath(), index));
	}

	/**
	 * Fetch a child (element or attribute) by key (index or name, respectively)
	 * 
	 * <p>
	 * Indices are distinguished from names by the presence or absence of brackets {@code []}. If
	 * the key is a bracket-enclosed index, this will retrieve a child, otherwise, it will retrieve
	 * an attribute.
	 * 
	 * @see #fetchAttribute(String)
	 * @see #fetchElement(String)
	 * @return a future which completes with the child
	 */
	public default CompletableFuture<?> fetchChild(String key) {
		if (PathUtils.isIndex(key)) {
			return fetchElement(PathUtils.parseIndex(key));
		}
		return fetchAttribute(key);
	}

	/**
	 * Fetch the children (elements and attributes) of this object which support the requested
	 * interface
	 * 
	 * <p>
	 * If no children support the given interface, the result is the empty set.
	 * 
	 * @param <T> the requested interface
	 * @param iface the class of the requested interface
	 * @return a future which completes with a name-value map of children supporting the given
	 *         interface
	 */
	public default <T extends TargetObject> //
	CompletableFuture<? extends Map<String, ? extends T>> fetchChildrenSupporting(
			Class<T> iface) {
		return fetchChildren().thenApply(m -> m.entrySet()
				.stream()
				.filter(e -> iface.isAssignableFrom(e.getValue().getClass()))
				.collect(Collectors.toMap(Entry::getKey, e -> iface.cast(e.getValue()))));
	}

	/**
	 * Fetch the value at the given sub-path from this object
	 * 
	 * <p>
	 * Extend this reference's path with the given sub-path and request that value from the same
	 * model.
	 * 
	 * @param sub the sub-path to the value
	 * @return a future which completes with the value or with {@code null} if the path does not
	 *         exist
	 */
	public default CompletableFuture<?> fetchValue(List<String> sub) {
		return getModel().fetchModelObject(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchValue(List)
	 */
	public default CompletableFuture<?> fetchValue(String... sub) {
		return fetchValue(List.of(sub));
	}

	/**
	 * Fetch the successor object at the given sub-path from this object
	 * 
	 * <p>
	 * Extend this reference's path with the given sub-path and request that object from the same
	 * model.
	 * 
	 * @param sub the sub-path to the successor
	 * @return a future which completes with the object or with {@code null} if it does not exist
	 */
	public default CompletableFuture<? extends TargetObject> fetchSuccessor(List<String> sub) {
		return getModel().fetchModelObject(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchSuccessor(List)
	 */
	public default CompletableFuture<? extends TargetObject> fetchSuccessor(String... sub) {
		return fetchSuccessor(List.of(sub));
	}

	/**
	 * Get a reference to a successor of this object
	 * 
	 * <p>
	 * Extend this reference's path with the given sub-path, creating a new reference in the same
	 * model. This is mere path manipulation. The referenced object may not exist.
	 * 
	 * @param sub the sub-path to the successor
	 * @return a reference to the successor
	 */
	public default TargetObjectRef getSuccessor(List<String> sub) {
		return getModel().createRef(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #getSuccessor(List)
	 */
	public default TargetObjectRef getSuccessor(String... sub) {
		return getSuccessor(List.of(sub));
	}

	/**
	 * Fetch the attributes of the model at the given sub-path from this object
	 * 
	 * @param sub the sub-path to the successor whose attributes to list
	 * @return a future map of attributes
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchSubAttributes(
			List<String> sub) {
		return getModel().fetchObjectAttributes(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchSubAttributes(List)
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchSubAttributes(
			String... sub) {
		return fetchSubAttributes(List.of(sub));
	}

	/**
	 * Fetch the attribute of a successor object, using a sub-path from this object
	 * 
	 * <p>
	 * Extends this object's path with the given sub-path and request that attribute from the same
	 * model.
	 * 
	 * @param sub the sub-path to the attribute
	 * @return a future which completes with the value or with {@code null} if it does not exist
	 */
	public default CompletableFuture<?> fetchSubAttribute(List<String> sub) {
		return getModel().fetchObjectAttribute(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchSubAttribute(List)
	 */
	public default CompletableFuture<?> fetchSubAttribute(String... sub) {
		return fetchSubAttribute(List.of(sub));
	}

	/**
	 * Fetch the elements of the model at the given sub-path from this object
	 * 
	 * @param sub the sub-path to the successor whose elements to list
	 * @return a future map of elements
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchSubElements(
			List<String> sub) {
		return getModel().fetchObjectElements(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchSubElements(List)
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchSubElements(
			String... sub) {
		return fetchSubElements(List.of(sub));
	}
}
