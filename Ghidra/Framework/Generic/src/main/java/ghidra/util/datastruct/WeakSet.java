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
package ghidra.util.datastruct;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.WeakHashMap;
import java.util.stream.Stream;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public abstract class WeakSet<T> implements Iterable<T> {

	private static final boolean WARN_ON_ANONYMOUS_VALUE =
		SystemUtilities.isInDevelopmentMode() || SystemUtilities.isInTestingMode();
	private static final String WARNING_MESSAGE = "Added an anonymous class from a method or " +
		"constructor.  Ghidra now has a policy of creating classes as top-level elements or " +
		"creating inline classes where the field of the class is being declared.  This prevents " +
		"accidental bugs whereby programmers add listeners to objects without maintaining a " +
		"reference to that listener.\nSee SCR 8267 for an example.";

	protected WeakHashMap<T, T> weakHashStorage;

	public WeakSet() {
		weakHashStorage = new WeakHashMap<>();
	}

	/**
	 * Looks for situations where clients <b>may</b> lose the values added to this class.  This
	 * most often happens when a client adds an anonymous, local listener to an object that is 
	 * using a WeakSet to store its listeners.  Our policy is to implement listeners at the 
	 * class field level so that they will not be flagged by this method. 
	 * 
	 * @param t The object to check
	 */
	protected void maybeWarnAboutAnonymousValue(T t) {
		if (!WARN_ON_ANONYMOUS_VALUE) {
			return;
		}

		// Note: sadly, this code does not work with labmda's, as we cannot get the enclosing
		//       method/constructor

		Class<? extends Object> clazz = t.getClass();
		if (!clazz.isAnonymousClass()) {
			return; // O.K.
		}

		Method enclosingMethod = clazz.getEnclosingMethod();
		if (enclosingMethod != null) {
			Msg.debug(this, "added an anonymous class created in a method: " + clazz.getName(),
				new Throwable());
			return;
		}

		Constructor<?> enclosingConstructor = clazz.getEnclosingConstructor();
		if (enclosingConstructor != null) {
			Msg.debug(this, WARNING_MESSAGE + "\nClass name: " + clazz.getName(), new Throwable());
		}
	}

//==================================================================================================
// Interface Methods
//==================================================================================================	

	/**
	 * Add the given object to the set
	 * @param t the object to add
	 */
	public abstract void add(T t);

	/**
	 * Remove the given object from the data structure
	 * @param t the object to remove
	 * 
	 */
	public abstract void remove(T t);

	/**
	 * Returns true if the given object is in this data structure
	 * @return true if the given object is in this data structure
	 */
	public abstract boolean contains(T t);

	/**
	 * Remove all elements from this data structure
	 */
	public abstract void clear();

	/**
	 * Return the number of objects contained within this data structure
	 * @return the size
	 */
	public abstract int size();

	/**
	 * Return whether this data structure is empty
	 * @return whether this data structure is empty
	 */
	public abstract boolean isEmpty();

	/**
	 * Returns a Collection view of this set.  The returned Collection is backed by this set.
	 * 
	 * @return a Collection view of this set.  The returned Collection is backed by this set.
	 */
	public abstract Collection<T> values();

	/**
	 * Returns a stream of the values of this collection.
	 * @return a stream of the values of this collection.
	 */
	public Stream<T> stream() {
		return values().stream();
	}

	@Override
	public String toString() {
		return values().toString();
	}
}
