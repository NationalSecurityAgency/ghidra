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
package agent.dbgeng.dbgeng;

/**
 * Handle to a module (program or library image).
 */
public interface DebugModule {
	public enum DebugModuleName {
		IMAGE, MODULE, LOADED_IMAGE, SYMBOL_FILE, MAPPED_IMAGE;
	}

	/**
	 * Get a name for the module.
	 * 
	 * @param which identifies which name
	 * @return the requested name, if available
	 */
	String getName(DebugModuleName which);

	/**
	 * Get the index assigned to this module.
	 * 
	 * @return the index
	 */
	int getIndex();

	/**
	 * Get the base address where this module is loaded, if applicable.
	 * 
	 * @return the base address
	 */
	long getBase();
}
