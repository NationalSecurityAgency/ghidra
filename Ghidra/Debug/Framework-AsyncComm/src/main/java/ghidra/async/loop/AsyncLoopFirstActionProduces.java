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

import java.util.function.Consumer;

import ghidra.async.AsyncUtils;

/**
 * The interface for the first action of a plain loop
 *
 * @see AsyncUtils#loop(ghidra.async.TypeSpec, AsyncLoopFirstActionProduces,
 *      ghidra.async.TypeSpec, AsyncLoopSecondActionConsumes)
 *
 * @param <R> the type of result for the whole loop
 * @param <T> the type of result produced, i.e., provided by the subordinate asynchronous task
 */
public interface AsyncLoopFirstActionProduces<R, T>
		extends Consumer<AsyncLoopHandlerForFirst<R, T>> {
	// Nothing
}
