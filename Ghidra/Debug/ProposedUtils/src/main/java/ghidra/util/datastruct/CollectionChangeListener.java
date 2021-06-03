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

public interface CollectionChangeListener<E> {
	@SuppressWarnings({ "rawtypes", "unchecked" })
	static <E> Class<CollectionChangeListener<E>> of(Class<E> cls) {
		return (Class) CollectionChangeListener.class;
	}

	default void elementAdded(E element) {
	}

	default void elementRemoved(E element) {
	}

	default void elementModified(E element) {
	}
}
