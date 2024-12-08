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
/**
 *
 */
package ghidra.framework.main.datatree;

import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.framework.plugintool.PluginTool;
import util.CollectionUtils;

/**
 * A handler to facilitate drag-n-drop for a list of Java {@link File} objects which is dropped
 * onto the Project data tree or a running Ghidra Tool (see {@link DataFlavor#javaFileListFlavor}).
 */
public final class JavaFileListHandler extends AbstractFileListFlavorHandler {

	@Override
	// This is for the FileOpenDataFlavorHandler for handling OS files dropped on a Ghidra Tool
	public void handle(PluginTool tool, Object transferData, DropTargetDropEvent e, DataFlavor f) {
		List<File> fileList = CollectionUtils.asList((List<?>) transferData, File.class);
		doImport(null, fileList, tool, tool.getToolFrame());
	}

	@Override
	// This is for the DataFlavorHandler interface for handling OS files dropped onto a DataTree
	public boolean handle(PluginTool tool, DataTree dataTree, GTreeNode destinationNode,
			Object transferData, int dropAction) {
		List<File> fileList = CollectionUtils.asList((List<?>) transferData, File.class);
		if (fileList.isEmpty()) {
			return false;
		}
		doImport(getDomainFolder(destinationNode), fileList, tool, dataTree);
		return true;
	}
}
