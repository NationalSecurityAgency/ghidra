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
package ghidra.app.plugin.core.datamgr.tree;

import java.util.Collections;
import java.util.List;

import javax.swing.Icon;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;

public class DataTypeNode extends DataTypeTreeNode {
	private final DataType dataType;
	private final String name;
	private String displayName;

	private boolean isCut;
	private boolean useHighlight = false;

	private String toolTipText;

	public DataTypeNode(DataType dataType) {
		this.dataType = dataType;
		this.name = dataType.getName();
		this.displayName = getCurrentDisplayName();
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof DataTypeNode) {
			return super.compareTo(node);
		}

		return 1; // DataTypeNodes always come after ****everything else****
	}

	public DataType getDataType() {
		return dataType;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (getClass() != o.getClass()) {
			return false;
		}
		DataTypeNode otherNode = (DataTypeNode) o;
		return dataType.equals(otherNode.dataType) && name.equals(otherNode.name);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (isFavorite()) {
			return DataTypeUtils.getFavoriteIcon(isCut);
		}

		Icon icon = null;
		if (dataType instanceof BuiltInDataType) {
			icon = DataTypeUtils.getBuiltInIcon(isCut);
		}
		else {
			icon = DataTypeUtils.getIconForDataType(dataType, isCut);
		}

		if (!isCut && useHighlight) {
			return DataTypeUtils.getHighlightIcon(icon);
		}

		return icon;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getToolTip() {
		if (toolTipText == null) {
			// HACK: SCR 4122 - TypeDefs currently have no way of knowing when the underlying
			//                  datatype changes and thus cannot update the tooltip cache
			if (dataType instanceof TypeDef) {
				return ToolTipUtils.getToolTipText(dataType);
			}
			toolTipText = ToolTipUtils.getToolTipText(dataType);
		}
		return toolTipText;
	}

	@Override
	public boolean isLeaf() {
		return true;
	}

	@Override
	public void valueChanged(Object newValue) {
		if (dataType.getName().equals(newValue)) {
			return;
		}

		String newName = newValue.toString();
		if (StringUtils.isBlank(newName)) {
			Msg.showError(getClass(), null, "Rename Failed", "Name cannot be empty.");
			return;
		}

		int transactionID = dataType.getDataTypeManager().startTransaction("rename");

		try {
			dataType.setName(newName);
		}
		catch (DuplicateNameException e) {
			Msg.showError(getClass(), null, "Rename Failed",
				"Data Type by the name " + newValue + " already exists in this category.");
		}
		catch (InvalidNameException exc) {
			String msg = exc.getMessage();
			if (msg == null) {
				msg = "Invalid name specified: " + newValue;
			}
			Msg.showError(getClass(), null, "Invalid Name Specified", exc.getMessage());
		}
		finally {
			dataType.getDataTypeManager().endTransaction(transactionID, true);
		}
	}

	@Override
	public boolean isEditable() {
		return isModifiable() && canRename();
	}

	/**
	 * Returns true if this dataType node uses and editor that is different than Java's default
	 * editor.
	 * @return true if this dataType node has a custom editor.
	 */
	public boolean hasCustomEditor() {
		return (dataType instanceof Composite) || (dataType instanceof Enum) ||
			(dataType instanceof FunctionDefinition) || hasCustomEditorForBaseDataType();
	}

	private boolean hasCustomEditorForBaseDataType() {
		DataType baseDataType = DataTypeUtils.getBaseDataType(dataType);
		return (baseDataType instanceof Composite) ||
			(baseDataType instanceof Enum || (dataType instanceof FunctionDefinition));
	}

	private boolean canRename() {
		return !(dataType instanceof BuiltInDataType ||
			dataType instanceof MissingBuiltInDataType || dataType instanceof Array ||
			dataType instanceof Pointer);
	}

	@Override
	public String toString() {
		return getName();
	}

	public boolean isFavorite() {
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		return dataTypeManager.isFavorite(dataType);
	}

	@Override
	public void setNodeCut(boolean isCut) {
		this.isCut = isCut;
		fireNodeChanged(getParent(), this);
	}

	@Override
	public boolean canCut() {
		return isModifiable();
	}

	@Override
	public boolean canPaste(List<GTreeNode> pastedNodes) {
		if (pastedNodes.size() != 1) {
			return false;
		}
		GTreeNode pastedNode = pastedNodes.get(0);
		return pastedNode instanceof DataTypeNode;
	}

	@Override
	public boolean isCut() {
		return isCut;
	}

	@Override
	public ArchiveNode getArchiveNode() {
		GTreeNode parent = getParent();
		if (parent == null) {
			return null; // could happen during tree mutations
		}

		return ((DataTypeTreeNode) parent).getArchiveNode();
	}

	@Override
	public boolean isModifiable() {
		ArchiveNode archiveNode = getArchiveNode();
		return archiveNode != null && archiveNode.isModifiable();
	}

	@Override
	public boolean canDelete() {
		return true;
	}

	public void dataTypeStatusChanged() {
		fireNodeChanged(getParent(), this);
	}

	public void dataTypeChanged() {
		toolTipText = null;
		fireNodeChanged(getParent(), this);
		GTree tree = getTree();
		if (tree != null) {
			tree.repaint(); // need to repaint in case related datatypes changes mod status.
		}
	}

	public String getDisplayName() {
		// note: we have to check the name each time, as the optional underlying 
		//       source archive may have changed.
		String currentDisplayName = getCurrentDisplayName();
		if (!displayName.equals(currentDisplayName)) {
			displayName = currentDisplayName;
			fireNodeChanged(getParent(), this);
		}
		return displayName;
	}

	private String getCurrentDisplayName() {

		String baseDisplayName = dataType.getName();

		UniversalID localID = dataType.getDataTypeManager().getUniversalID();
		SourceArchive sourceArchive = dataType.getSourceArchive();
		if (sourceArchive != null && sourceArchive.getArchiveType() != ArchiveType.BUILT_IN &&
			!sourceArchive.getSourceArchiveID().equals(localID)) {
			return baseDisplayName + "  (" + sourceArchive.getName() + ")";
		}

		return baseDisplayName;
	}

	@Override
	protected List<GTreeNode> generateChildren() {
		return Collections.emptyList();
	}
}
