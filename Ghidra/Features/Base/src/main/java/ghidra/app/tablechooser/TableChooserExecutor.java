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
package ghidra.app.tablechooser;

public interface TableChooserExecutor {

	/**
	 * A short name suitable for display in the "apply" button that indicates what the "apply"
	 * action does.
	 * @return A short name suitable for display in the "apply" button that indicates what the "apply"
	 * action does.
	 */
	public String getButtonName();

	/**
	 * Applies this executors action to the given rowObject.  Return true if the given object 
	 * should be removed from the table. 
	 * 
	 * @param rowObject the AddressRowObject to be executed upon
	 * @return true if the rowObject should be removed from the table, false otherwise
	 */
	public boolean execute(AddressableRowObject rowObject);
}
