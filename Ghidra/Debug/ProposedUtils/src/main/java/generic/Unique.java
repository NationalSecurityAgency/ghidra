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
package generic;

import java.util.Iterator;

/**
 * Some utilities for when singleton collections are expected
 */
public interface Unique {

	/**
	 * Assert that exactly one element is in an iterable and get that element
	 * 
	 * @param <T> the type of element
	 * @param col the iterable
	 * @return the element
	 * @throws AssertionError if no element or many elements exist in the iterable
	 */
	static <T> T assertOne(Iterable<T> col) {
		Iterator<T> it = col.iterator();
		if (!it.hasNext()) {
			throw new AssertionError("Expected exactly one. Got none.");
		}
		T result = it.next();
		if (it.hasNext()) {
			throw new AssertionError("Expected exactly one. Got many.");
		}
		return result;
	}

	/**
	 * Assert that at most one element is in an iterable and get that element or {@code null}
	 * 
	 * @param <T> the type of element
	 * @param col the iterable
	 * @return the element or {@code null} if empty
	 * @throws AssertionError if many elements exist in the iterable
	 */
	static <T> T assertAtMostOne(Iterable<T> col) {
		Iterator<T> it = col.iterator();
		if (!it.hasNext()) {
			return null;
		}
		T result = it.next();
		if (it.hasNext()) {
			throw new AssertionError("Expected at most one. Got many.");
		}
		return result;
	}
}
