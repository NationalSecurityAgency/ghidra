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
package ghidra.app.plugin.core.datamgr.util;

import ghidra.app.plugin.core.datamgr.DataTypeSyncInfo;
import ghidra.app.plugin.core.datamgr.DataTypeSynchronizer;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.awt.Component;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.SwingUtilities;

import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;

/**
 * Task for handling drop operations.
 */
public class DataTypeTreeCopyMoveTask extends Task {
	public enum ActionType {
		COPY, MOVE
	}

	private GTreeNode destinationNode;
	private List<GTreeNode> droppedNodeList;
	private ActionType actionType;
	private Archive destinationArchive;
	private Component component;
	private DataTypeConflictHandler conflictHandler;

	/**
	 *
	 * @param treePanel
	 * @param destNode  destination node for the data; could be null
	 * if this is a "drop anywhere" situation.
	 * @param data may be a data type or a list of DataTypeTreeNodes
	 * @param chosenFlavor data flavor that dictates what data is
	 * @param actionType either ActionType.COPY or ActionTYPE.MOVE
	 * @param conflictHandler data type conflict handler
	 */
	public DataTypeTreeCopyMoveTask(GTreeNode destinationNode, List<GTreeNode> droppedNodeList,
			ActionType actionType, Component component, DataTypeConflictHandler conflictHandler) {
		super("Drag/Drop", true, true, true);
		this.destinationNode = destinationNode;
		this.droppedNodeList = droppedNodeList;
		this.actionType = actionType;
		this.component = component;
		this.destinationArchive = findArchive(destinationNode);
		this.conflictHandler = conflictHandler;
	}

	private Archive findArchive(GTreeNode node) {
		while (node != null) {
			if (node instanceof ArchiveNode) {
				return ((ArchiveNode) node).getArchive();
			}
			node = node.getParent();
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void run(TaskMonitor monitor) {
		monitor.setMessage("Drag/Drop Categories/Data Types");
		monitor.initialize(droppedNodeList.size());
		droppedNodeList = filterList(droppedNodeList);

		GTreeNode firstNode = droppedNodeList.get(0);
		Archive sourceArchive = findArchive(firstNode);
		for (GTreeNode node : droppedNodeList) {
			if (sourceArchive != findArchive(node)) {
				Msg.showError(this, component, "Copy Failed",
					"All dragged data types must be from the same archive!");
				return;
			}
		}

		if (sourceArchive != destinationArchive &&
			!(destinationArchive instanceof ProgramArchive) &&
			(sourceArchive instanceof ProgramArchive) && sourceArchive.isModifiable()) {
			try {
				associateDataTypes(sourceArchive,
					destinationArchive.getDataTypeManager().getLocalSourceArchive());
			}
			catch (CancelledException e) {
				return;
			}
		}
		int transactionID =
			destinationArchive.getDataTypeManager().startTransaction("Copy/Move Category/DataType");
		try {
			if (destinationNode instanceof DataTypeNode) {
				dragNodeToDataType(monitor);
			}
			else {
				dragNodesToCategory(monitor);
			}
		}
		finally {
			destinationArchive.getDataTypeManager().endTransaction(transactionID, true);
		}
	}

	/**
	 *
	 * @param archive
	 * @param source
	 * @param confirmed is a single element array containing tri-state Boolean flag which
	 * has the following states:
	 *   null - (initial state) user has not yet been prompted
	 *   true - user has confirmed performing associations
	 *   false - user has denied performing associations
	 * @throws CancelledException if user has cancelled the operation
	 */
	private void associateDataTypes(Archive archive, SourceArchive source)
			throws CancelledException {
		DataTypeManager dtm = archive.getDataTypeManager();
		int transactionID = dtm.startTransaction("Associate DataTypes");
		try {
			DataTypeAssociationConfirmation confirmation = new DataTypeAssociationConfirmation();
			for (GTreeNode node : droppedNodeList) {
				if (node instanceof DataTypeNode) {
					DataType replacementDataType = ((DataTypeNode) node).getDataType();
					if (!isLocal(replacementDataType)) {
						continue;
					}
					if (!confirmation.isConfirmed()) {
						return;
					}
					dtm.associateDataTypeWithArchive(replacementDataType, source);
				}
				else if (node instanceof CategoryNode) {
					Category cat = ((CategoryNode) node).getCategory();
					associateDataTypes(cat, dtm, source, confirmation);
					if (confirmation.haveAskedUser() && !confirmation.isConfirmed()) {
						return;
					}
				}
			}
		}
		finally {
			archive.getDataTypeManager().endTransaction(transactionID, true);
		}
	}

	private void associateDataTypes(Category cat, DataTypeManager dtm, SourceArchive source,
			DataTypeAssociationConfirmation confirmation) throws CancelledException {
		DataType[] dataTypes = cat.getDataTypes();
		for (DataType dataType : dataTypes) {
			if (!isLocal(dataType)) {
				continue;
			}
			if (!confirmation.isConfirmed()) {
				return;
			}
			dtm.associateDataTypeWithArchive(dataType, source);
		}
		Category[] categories = cat.getCategories();
		for (Category category : categories) {
			associateDataTypes(category, dtm, source, confirmation);
			if (confirmation.haveAskedUser() && !confirmation.isConfirmed()) {
				return;
			}
		}
	}

	private class DataTypeAssociationConfirmation {
		Boolean confirmed = null;

		boolean isConfirmed() throws CancelledException {
			if (confirmed == null) {
				int result = askToAssociateDataTypes();
				if (result == OptionDialog.NO_OPTION) {
					confirmed = false;
				}
				else if (result == OptionDialog.YES_OPTION) {
					confirmed = true;
				}
				else {
					throw new CancelledException();
				}
			}
			return confirmed;
		}

		boolean haveAskedUser() {
			return confirmed != null;
		}
	}

	private void dragNodesToCategory(TaskMonitor monitor) {
		int count = 0;
		Category destinationCategory = getCategory(destinationNode);
		Archive sourceArchive = findArchive(droppedNodeList.get(0));
		for (GTreeNode node : droppedNodeList) {
			monitor.setProgress(count++);
			if (monitor.isCancelled()) {
				break;
			}

			monitor.setMessage("Adding " + node.getName());

			// COPY is only allowed action if the source and destination archives are different.
			if (actionType == ActionType.COPY || sourceArchive != destinationArchive) {
				copyNode(destinationCategory, node, monitor);
			}
			else {
				moveNode(destinationCategory, node, monitor);
			}
		}
	}

	private void copyNode(Category destinationCategory, GTreeNode node, TaskMonitor monitor) {
		if (node instanceof DataTypeNode) {
			DataType nodeDt = ((DataTypeNode) node).getDataType();
			DataTypeManager dtm = destinationCategory.getDataTypeManager();
			boolean withinDataTypeManager = (dtm == nodeDt.getDataTypeManager());
			DataType dataType =
				!withinDataTypeManager ? nodeDt.clone(nodeDt.getDataTypeManager())
						: nodeDt.copy(nodeDt.getDataTypeManager());
			if (withinDataTypeManager &&
				dataType.getCategoryPath().equals(destinationCategory.getCategoryPath())) {
				renameAsCopy(destinationCategory, dataType);
			}
			final DataType resolvedDT = destinationCategory.addDataType(dataType, conflictHandler);
			if (resolvedDT instanceof Pointer || resolvedDT instanceof Array ||
				resolvedDT instanceof BuiltInDataType ||
				resolvedDT instanceof MissingBuiltInDataType) {
				return;
			}
			if (!resolvedDT.getCategoryPath().equals(destinationCategory.getCategoryPath())) {
				// We are in a task, must show dialog in the swing thread.
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						String msg =
							"Another copy of this data-type already exists at " +
								resolvedDT.getPathName();
						Msg.showInfo(getClass(), component, "DataType copy failed!", msg);
					}
				});
			}
		}
		else if (node instanceof CategoryNode) {
			Category category = ((CategoryNode) node).getCategory();
			copyCategory(destinationCategory, category, monitor);
		}
	}

	private void renameAsCopy(Category destinationCategory, DataType dataType) {
		String baseName = dataType.getName();
		String prefix = "Copy_";
		String suffix = "of_";
		if (baseName.startsWith(prefix)) {
			int indexOf = baseName.indexOf(suffix);
			if (indexOf > 4) {
				if (indexOf == 5) {
					baseName = baseName.substring(indexOf + 3);
				}
				else {
					if (indexOf > 5) {
						if ((baseName.charAt(indexOf - 1) == '_')) {
							String copyNumber = baseName.substring(5, indexOf - 1);
							try {
								Integer.parseInt(copyNumber);
								baseName = baseName.substring(indexOf + 3);
							}
							catch (NumberFormatException e) {
								// If can't parse number then assume not one of our numbered copies.
							}

						}
					}
				}
			}
		}
		String copyName = getNextCopyName(destinationCategory, baseName);
		try {
			dataType.setName(copyName);
		}
		catch (InvalidNameException e) {
			Msg.error(this, "Problem creating copy of " + baseName, e);
		}
		catch (DuplicateNameException e) {
			Msg.error(this, "Problem creating copy of " + baseName, e);
		}
	}

	private String getNextCopyName(final Category destinationCategory, final String baseName) {
		String prefix = "Copy_";
		String suffix = "of_";
		String copyName = prefix + suffix + baseName;
		if (destinationCategory.getDataType(copyName) == null) {
			return copyName;
		}
		for (int i = 2; i < Integer.MAX_VALUE; i++) {
			copyName = prefix + i + "_" + suffix + baseName;
			if (destinationCategory.getDataType(copyName) == null) {
				return copyName;
			}
		}
		return baseName;
	}

	private void moveNode(Category destinationCategory, GTreeNode node, TaskMonitor monitor) {
		if (node instanceof DataTypeNode) {
			DataType dataType = ((DataTypeNode) node).getDataType();
			moveDataType(destinationCategory, dataType);
		}
		else if (node instanceof CategoryNode) {
			Category category = ((CategoryNode) node).getCategory();
			moveCategory(destinationCategory, category, monitor);
		}
	}

	private void moveCategory(Category destinationCategory, Category category, TaskMonitor monitor) {
		if (category.getParent() == destinationCategory) { // moving to same place
			return;
		}
		try {
			CategoryPath path = destinationCategory.getCategoryPath();
			if (path.isAncestorOrSelf(category.getCategoryPath())) {
				Msg.showError(this, component, "Move Failed",
					"Cannot move a parent node onto a child node");
				return;
			}

			destinationCategory.moveCategory(category, monitor);
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, component, "Move Failed", "Move failed due to duplicate name:\n" +
				e.getMessage());
		}
	}

	private void moveDataType(Category destinationCategory, DataType dataType) {
		if (dataType.getCategoryPath().equals(destinationCategory.getCategoryPath())) {
			Msg.showError(this, component, "Move Failed", "DataType is already in this category.");
			return;
		}
		try {
			destinationCategory.moveDataType(dataType, conflictHandler);
		}
		catch (DataTypeDependencyException e) {
			Msg.showError(this, component, "Move Failed", e.getMessage());
		}
	}

	private void copyCategory(Category destinationCategory, Category category, TaskMonitor monitor) {
		CategoryPath destinationPath = destinationCategory.getCategoryPath();
		boolean withinSameDataTypeManager = (destinationCategory.getDataTypeManager() == category.getDataTypeManager());
		if (withinSameDataTypeManager && destinationPath.isAncestorOrSelf(category.getCategoryPath())) {
			Msg.showError(this, component, "Copy Failed",
				"Cannot copy a parent node onto a child node");
			return;
		}
		destinationCategory.copyCategory(category, conflictHandler, monitor);
	}

	private Category getCategory(GTreeNode node) {
		if (node instanceof ArchiveNode) {
			return ((ArchiveNode) node).getArchive().getDataTypeManager().getRootCategory();
		}
		if (node instanceof CategoryNode) {
			return ((CategoryNode) node).getCategory();
		}
		throw new AssertException(
			"Expected node to be either an ArchiveNode or CategoryNode but was " + node.getClass());
	}

	private boolean isAssociatedEitherWay(DataType dataType1, DataType dataType2) {
		return isAssociated(dataType1, dataType2) || isAssociated(dataType2, dataType1);
	}

	private boolean isAssociated(DataType sourceDataType, DataType destinationDataType) {
		UniversalID destinationID = destinationDataType.getUniversalID();
		if (destinationID == null || !destinationID.equals(sourceDataType.getUniversalID())) {
			return false;
		}
		if (!destinationDataType.getSourceArchive().getSourceArchiveID().equals(
			sourceDataType.getSourceArchive().getSourceArchiveID())) {
			return false;
		}
		return isLocal(sourceDataType);
	}

	private boolean isLocal(DataType dataType) {
		return dataType.getSourceArchive().getSourceArchiveID().equals(
			dataType.getDataTypeManager().getUniversalID());
	}

	private void dragNodeToDataType(TaskMonitor monitor) {
		DataType destinationDataType = ((DataTypeNode) destinationNode).getDataType();
		GTreeNode node = droppedNodeList.get(0); // there must be exactly one and it must
		// be a dataTypeNode, because of isValidDropSite()
		DataType replacementDataType = ((DataTypeNode) node).getDataType();
		Archive sourceArchive = findArchive(node);
		if (sourceArchive != destinationArchive) {
			if (isAssociatedEitherWay(replacementDataType, destinationDataType)) {
				if (isLocal(destinationDataType)) {
					DataTypeSyncInfo syncInfo =
						new DataTypeSyncInfo(replacementDataType,
							destinationDataType.getDataTypeManager());
					if (!syncInfo.canCommit()) {
						Msg.showInfo(getClass(), component, "Commit Data Type",
							"No changes to commit");
					}
					// destination data-type is local to an archive
					else if (confirmCommit()) {
						// if the destination dataType is local to its dataTypeManager 
						// then we are committing.
						DataTypeSynchronizer.commit(destinationDataType.getDataTypeManager(),
							replacementDataType);
					}
				}
				else { // else we are updating
					DataTypeSyncInfo syncInfo =
						new DataTypeSyncInfo(destinationDataType,
							replacementDataType.getDataTypeManager());
					if (!syncInfo.canUpdate()) {
						Msg.showInfo(getClass(), component, "Update Data Type",
							"No changes to copy");
					}
					else if (confirmUpdate()) {
						DataTypeSynchronizer.update(destinationDataType.getDataTypeManager(),
							replacementDataType);
					}
				}
				return;
			}
			actionType = ActionType.COPY;
			replacementDataType =
				replacementDataType.clone(replacementDataType.getDataTypeManager());
		}
		else if (actionType == ActionType.COPY) { // Copy within a single data type manager.
			replacementDataType =
				replacementDataType.copy(replacementDataType.getDataTypeManager());
		}

		replaceDataType(destinationDataType, replacementDataType);
	}

	private boolean confirmCommit() {
		return confirm("Commit Data Type?",
			"Do you want to commit the changes to this data type back to the source Archive? \n"
				+ "(Warning: any changes in the source archive will be overwritten.)");
	}

	private boolean confirmUpdate() {
		return confirm("Update Data Type?",
			"Do you want to update this data type with the changes in the source Archive?\n"
				+ "(Warning: any local changes will be overwritten.)");
	}

	private boolean confirm(final String title, final String message) {
		final BooleanResultsContainer results = new BooleanResultsContainer();
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					int selectedOption = OptionDialog.showYesNoDialog(component, title, message);
					results.value = selectedOption == OptionDialog.OPTION_ONE;
				}
			});
		}
		catch (InterruptedException e1) {
		}
		catch (InvocationTargetException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		return results.value;
	}

	private int askToAssociateDataTypes() {
		final IntResultsContainer results = new IntResultsContainer();
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					results.value =
						OptionDialog.showYesNoCancelDialog(component, "Associate DataTypes?",
							"Do you want to associate local datatypes with the target archive?");
				}
			});
		}
		catch (InterruptedException e1) {
		}
		catch (InvocationTargetException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		return results.value;
	}

	class BooleanResultsContainer {
		public boolean value;
	}

	class IntResultsContainer {
		public int value;
	}

	private void replaceDataType(final DataType existingDT, final DataType replacementDT) {

		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					int selectedOption =
						OptionDialog.showYesNoDialog(component, "Replace Data Type?", "Replace " +
							existingDT.getPathName() + "\nwith " + replacementDT.getPathName() +
							"?");

					if (selectedOption == OptionDialog.OPTION_ONE) {
						try {
							DataTypeManager dtMgr = existingDT.getDataTypeManager();
							dtMgr.replaceDataType(existingDT, replacementDT, true);
						}
						catch (DataTypeDependencyException e) {
							Msg.showError(this, component, "Replace Failed", e.getMessage());
						}
					}
				}
			});
		}
		catch (InterruptedException e1) {
		}
		catch (InvocationTargetException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	private List<GTreeNode> filterList(List<GTreeNode> nodeList) {
		Set<GTreeNode> nodeSet = new HashSet<GTreeNode>(nodeList);
		List<GTreeNode> filteredList = new ArrayList<GTreeNode>();

		for (GTreeNode node : nodeSet) {
			if (!containsAncestor(nodeSet, node)) {
				filteredList.add(node);
			}
		}

		return filteredList;
	}

	private boolean containsAncestor(Set<GTreeNode> nodeSet, GTreeNode node) {
		GTreeNode parent = node.getParent();
		if (parent == null) {
			return false;
		}

		if (nodeSet.contains(parent)) {
			return true;
		}

		return containsAncestor(nodeSet, parent);
	}
}
