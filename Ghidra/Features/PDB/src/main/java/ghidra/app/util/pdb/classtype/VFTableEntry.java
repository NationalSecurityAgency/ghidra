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
package ghidra.app.util.pdb.classtype;

import ghidra.app.util.SymbolPath;
import ghidra.program.model.data.Pointer;

/**
 * Represents an entry within a virtual function table
 */
public interface VFTableEntry extends VXTEntry {

	/**
	 * Sets the original path of the function
	 * @param path the symbol path
	 */
	public void setOriginalPath(SymbolPath path);

	/**
	 * Gets the original path of the function
	 * @return the symbol path
	 */
	public SymbolPath getOriginalPath();

	/**
	 * Sets the override path of the function
	 * @param path the symbol path
	 */
	public void setOverridePath(SymbolPath path);

	/**
	 * Gets the override path of the function
	 * @return the symbol path
	 */
	public SymbolPath getOverridePath();

	/**
	 * Sets the pointer to the function definition type
	 * @param pointer the pointer to the funciton definition type
	 */
	public void setFunctionPointer(Pointer pointer);

	/**
	 * Returns the pointer to the function definition type
	 * @return the pointer to the function definition type
	 */
	public Pointer getFunctionPointer();

}
