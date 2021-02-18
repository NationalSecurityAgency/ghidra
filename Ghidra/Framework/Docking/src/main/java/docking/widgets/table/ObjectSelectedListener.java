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
package docking.widgets.table;

/**
 * An interface for clients to know when an object is selected and when the selection is cleared
 *
 * @param <T> the object type
 */
public interface ObjectSelectedListener<T> {

	/**
	 * When an object is select; null if the selection is cleared
	 * @param t the object selected or null
	 */
	public void objectSelected(T t);
}
