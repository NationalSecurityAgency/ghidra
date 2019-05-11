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

/**
 * Factory for creating containers to use in various threading environments
 */
public class WeakDataStructureFactory {

	/**
	 * Use when all access are on a single thread, such as the Swing thread.
	 * 
	 * @return a new WeakSet
	 */
	public static <T> WeakSet<T> createSingleThreadAccessWeakSet() {
		return new ThreadUnsafeWeakSet<T>();
	}

	/**
	 * Use when mutations outweigh iterations.
	 * 
	 * @return a new WeakSet
	 * @see CopyOnReadWeakSet
	 */
	public static <T> WeakSet<T> createCopyOnReadWeakSet() {
		return new CopyOnReadWeakSet<T>();
	}

	/**
	 * Use when iterations outweigh mutations.
	 * 
	 * @return a new WeakSet
	 * @see CopyOnWriteWeakSet
	 */
	public static <T> WeakSet<T> createCopyOnWriteWeakSet() {
		return new CopyOnWriteWeakSet<T>();
	}
}
