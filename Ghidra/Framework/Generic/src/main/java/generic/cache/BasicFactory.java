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
package generic.cache;

public interface BasicFactory<T> {

	/**
	 * Creates an instance of {@link T}.
	 * 
	 * @return the new instance of T
	 * @throws Exception any Exception encountered during creation
	 */
	public T create() throws Exception;

	/**
	 * Called when clients are finished with the given item and it should be disposed.
	 * 
	 * @param t the item to dispose.
	 */
	public void dispose(T t);
}
