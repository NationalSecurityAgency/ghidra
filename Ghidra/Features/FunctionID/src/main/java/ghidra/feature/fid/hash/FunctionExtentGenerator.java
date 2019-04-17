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
package ghidra.feature.fid.hash;

import java.util.List;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;

/**
 * FunctionExtentGenerator is an interface with a single method,
 * calculateExtent.
 *
 */
public interface FunctionExtentGenerator {
	/**
	 * Calculates the extent of a function, and returns a deterministic, 
	 * flow-ordered list of code units comprising the function.
	 * @param func the function on which to calculate the extent
	 * @return the list of codeunits in the function
	 */
	public List<CodeUnit> calculateExtent(Function func);
}
