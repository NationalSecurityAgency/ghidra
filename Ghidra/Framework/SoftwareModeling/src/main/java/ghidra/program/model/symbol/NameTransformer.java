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
 * Interface to transform (shorten, simplify) names of data-types, functions, and name spaces
 * for display.
 */
public interface NameTransformer {

	/**
	 * Return a transformed version of the given input.  If no change is made, the original
	 * String object is returned.
	 * @param input is the name to transform
	 * @return the transformed version
	 */
	public String simplify(String input);
}
