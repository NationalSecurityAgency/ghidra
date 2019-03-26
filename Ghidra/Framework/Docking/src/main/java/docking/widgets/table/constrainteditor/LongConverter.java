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
package docking.widgets.table.constrainteditor;

/**
 * Interface used by number constraints. This allows all the integer number constraints (byte,short
 * int, long) to share the same editor (which uses long values). This interface allows the editor
 * values to be converted back to T.
 *
 * @param <T> The number type
 */
public interface LongConverter<T> {

	/**
	 * Converts a long value back to a T
	 *
	 * @param value the long value.
	 * @return the long value converted to T
	 */
	public T fromLong(long value);

}
