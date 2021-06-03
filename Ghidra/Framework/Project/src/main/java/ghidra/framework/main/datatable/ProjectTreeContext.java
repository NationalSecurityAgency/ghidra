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

import javax.swing.tree.TreePath;

import ghidra.framework.main.datatree.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;

/**
 * Common methods appropriate for both the {@link FrontEndProjectTreeContext} and the 
 * {@link DialogProjectTreeContext}.  The project tree actions require that the contexts be
 * separate even though they need many of the same methods. By extracting the methods to this
 * interface, the contexts can be kept separate, but can share action code.
 */
public interface ProjectTreeContext {

	/**
	 * Returns the number of folders selected in the tree.
	 * @return the number of folders selected in the tree.
	 */
	public int getFolderCount();

	/**
	 * Returns the number of files selected in the tree.
	 * @return the number of files selected in the tree.
	 */
	public int getFileCount();

	/**
	 * Returns a list of {@link DomainFolder}s selected in the tree.
	 * @return  a list of {@link DomainFolder}s selected in the tree.
	 */
	public List<DomainFolder> getSelectedFolders();

	/**
	 * Returns a list of {@link DomainFile}s selected in the tree.
	 * @return  a list of {@link DomainFile}s selected in the tree.
	 */
	public List<DomainFile> getSelectedFiles();

	/**
	 * Returns the project data tree component.
	 * @return  the project data tree component.
	 */
	public DataTree getTree();

	/**
	 * Returns the list of selected {@link TreePath}s selected.
	 * @return  the list of selected {@link TreePath}s selected.
	 */
	public TreePath[] getSelectionPaths();

}
