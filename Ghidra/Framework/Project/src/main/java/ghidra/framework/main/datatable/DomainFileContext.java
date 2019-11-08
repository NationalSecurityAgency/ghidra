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
 * A context that provides to the client
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

	/**
	 * Returns true if the the current context is busy.  This is used by actions to signal to
	 * the environment that they are performing a long-running operation.
	 * @return true if busy
	 */
	public boolean isBusy();

	/**
	 * Sets this context to busy.  This is used by actions to signal to
	 * the environment that they are performing a long-running operation.
	 * <p>
	 * Note: context state is not maintained by the tool.  Thus, the notion of being busy will
	 * not be maintained across calls to <code>getActionContext()</code>.  Further, if implementors
	 * wish to track business, then they must do so themselves.
	 * 
	 * @param isBusy true if busy
	 */
	public void setBusy(boolean isBusy);
}
