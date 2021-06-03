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
package ghidra.app.plugin.core.datamgr.actions;

import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.program.model.data.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

/**
 * A class to 1) hold related data for creating a new data type and 2) to validate the given 
 * data when the requested info is based upon the a disallowed condition (e.g., creating a data
 * type in the built-in archive).
 */
class DerivativeDataTypeInfo {

	private final DataTypeManagerPlugin plugin;

	//
	// These values may change, depending upon which archive from which 
	// the user is attempting to edit
	//
	private DataTypeManager dataTypeManager;
	private CategoryPath categoryPath;
	private GTreeNode parentNode;

	DerivativeDataTypeInfo(DataTypeManagerPlugin plugin, DataTypeArchiveGTree gTree,
			GTreeNode selectedNode, DataType baseDataType) {
		this.plugin = plugin;
		parentNode = selectedNode.getParent();
		categoryPath = baseDataType.getCategoryPath();
		dataTypeManager = baseDataType.getDataTypeManager();
		if (dataTypeManager instanceof BuiltInDataTypeManager) {
			//
			// Built-in archive is not modifiable.  Put the new type in the program archive and 
			// in the root category
			// 
			dataTypeManager = plugin.getProgramDataTypeManager();
			SystemUtilities.assertTrue(dataTypeManager != null, "Cannot create a " +
				getClass().getSimpleName() + " instance from the built-in data type manager when " +
				"no program is open");

			categoryPath = new CategoryPath("/");
			parentNode = getProgramArchiveNode(gTree);
		}
	}

	DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	CategoryPath getCategoryPath() {
		return categoryPath;
	}

	GTreeNode getParentNode() {
		return parentNode;
	}

	private ArchiveNode getProgramArchiveNode(DataTypeArchiveGTree tree) {

		DataTypeManager manager = plugin.getProgramDataTypeManager();
		GTreeNode rootNode = tree.getModelRoot();
		List<GTreeNode> children = rootNode.getChildren();
		for (GTreeNode node : children) {
			ArchiveNode archiveNode = (ArchiveNode) node;
			Archive archive = archiveNode.getArchive();
			if (archive.getDataTypeManager() == manager) {
				return archiveNode;
			}
		}

		// validated in isAddToPopup()
		throw new AssertException("Somehow program node is opened in the tool");
	}
}
