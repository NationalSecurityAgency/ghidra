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
package ghidra.app.util.bin.format.golang;

import ghidra.program.model.data.CategoryPath;

/**
 * Misc constant values for golang
 */
public class GoConstants {
	public static final String GOLANG_CSPEC_NAME = "golang";

	/**
	 * Category path to place golang types in
	 */
	public static final CategoryPath GOLANG_CATEGORYPATH = new CategoryPath("/golang");

	public static final String GOLANG_ABI_INTERNAL_CALLINGCONVENTION_NAME = "abi-internal";
	public static final String GOLANG_ABI0_CALLINGCONVENTION_NAME = "abi0";
	public static final String GOLANG_DUFFZERO_CALLINGCONVENTION_NAME = "duffzero";
	public static final String GOLANG_DUFFCOPY_CALLINGCONVENTION_NAME = "duffcopy";
}

