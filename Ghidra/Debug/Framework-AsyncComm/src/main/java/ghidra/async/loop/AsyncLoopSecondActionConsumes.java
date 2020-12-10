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
package ghidra.async.loop;

import java.util.function.BiConsumer;

import ghidra.async.AsyncUtils;

/**
 * The interface for the second or only action of certain loops
 * 
 * @see AsyncUtils#loop(ghidra.async.TypeSpec, AsyncLoopFirstActionProduces,
 *      ghidra.async.TypeSpec, AsyncLoopSecondActionConsumes)
 * @see AsyncUtils#each(ghidra.async.TypeSpec, java.util.Iterator,
 *      AsyncLoopFirstActionConsumesAndProduces, ghidra.async.TypeSpec,
 *      AsyncLoopSecondActionConsumes)
 * @see AsyncUtils#each(ghidra.async.TypeSpec, java.util.Iterator,
 *      AsyncLoopSecondActionConsumes)
 *
 * @param <R> the type of result for the whole loop
 * @param <T> the type of object consumed, i.e., provided by the controlling iterator or the
 *            subordinate asynchronous task
 */
public interface AsyncLoopSecondActionConsumes<R, T>
		extends BiConsumer<T, AsyncLoopHandlerForSecond<R>> {
	// Nothing
}
