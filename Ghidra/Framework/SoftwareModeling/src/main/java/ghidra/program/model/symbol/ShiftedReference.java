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
package ghidra.program.model.symbol;

/**
 * <code>ShiftedReference</code> is a memory reference whose "to" address is
 * computed from a base value left shifted by a shift amount.
 */
public interface ShiftedReference extends Reference {

	/**
	 * Returns the left shift amount.
	 * @return the shift
	 */
	public int getShift();

	/**
	 * Returns the base value.
	 * @return the value
	 */
	public long getValue();
}
