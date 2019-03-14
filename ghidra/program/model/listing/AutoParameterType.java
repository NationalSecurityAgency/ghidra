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
package ghidra.program.model.listing;

/**
 * <code>AutoParameterType</code> defines the various
 * types of auto-parameters.
 */
public enum AutoParameterType {

	/**
	 * <code>THIS</code> corresponds to the object pointer parameter associated
	 * with a __thiscall calling convention and passed as a hidden parameter
	 */
	THIS("this"),

	/**
	 * <code>RETURN_STORAGE_PTR</code> corresponds to a caller allocated return
	 * storage pointer passed as a hidden parameter
	 */
	RETURN_STORAGE_PTR("__return_storage_ptr__");

	private String displayName;

	private AutoParameterType(String displayName) {
		this.displayName = displayName;
	}

	public String getDisplayName() {
		return displayName;
	}

}
