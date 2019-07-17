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
package ghidra.app.plugin.core.searchmem.mask;

/**
 * Represents a filter for a single instruction. This defines what portions of the instruction will
 * be masked.
 */
class SLMaskControl {
	
	private boolean useOps = false;
	private boolean useConst = false;

	/**
	 * Constructor. 
	 * 
	 * @param useOperands
	 * @param constant
	 */
	SLMaskControl(boolean useOperands, boolean constant) {
		useOps = useOperands;
		useConst = constant;
	}

	boolean useOperands() {
		return useOps;
	}

	boolean useConst() {
		return useConst;
	}
}
