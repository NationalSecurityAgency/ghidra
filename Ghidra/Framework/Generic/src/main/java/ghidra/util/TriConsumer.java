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
package ghidra.util;

import java.util.function.BiConsumer;

/**
 * Patterned after {@link BiConsumer}.
 * 
 * @param <T>
 * @param <U>
 * @param <V>
 */
@FunctionalInterface
public interface TriConsumer<T, U, V> {
	/**
	 * Performs this operation on the given arguments.
	 *
	 * @param t the first input argument
	 * @param u the second input argument
	 * @param v the third input argument
	 */
	void accept(T t, U u, V v);
}
