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
package ghidra.framework.main.datatable;

import java.util.List;

import ghidra.framework.model.DomainFile;

/**
 * A context that provides information to actions about domain files that are selected in the tool
 */
public interface DomainFileContext {

	/**
	 * The selected files or empty if no files are selected
	 * @return the files
	 */
	public List<DomainFile> getSelectedFiles();

	/**
	 * Returns the count of selected files
	 * @return the count of selected files
	 */
	public int getFileCount();

	/**
	 * True if the current set of files is in the active project (false implies a non-active, 
	 * read-only project)
	 * 
	 * @return true if in the active project
	 */
	public boolean isInActiveProject();
}
