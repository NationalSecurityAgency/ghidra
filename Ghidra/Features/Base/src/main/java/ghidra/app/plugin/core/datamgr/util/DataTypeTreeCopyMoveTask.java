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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeState;
import ghidra.app.plugin.core.datamgr.DataTypeSyncInfo;
import ghidra.app.plugin.core.datamgr.DataTypeSynchronizer;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.ProgramArchive;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for handling drop operations.
 */
public class DataTypeTreeCopyMoveTask extends Task {

	// If the total number of nodes is small, we won't need to collapse the tree before deleting
	// the nodes to avoid excess tree events.  This number is very arbitrary.  This number is 
	// used to compare the number of dragged nodes, which may include categories whose child
	// count is not reflected in this number.  This could mean that thousands of nodes will be
	// processed, but the actual drag count could be much less.
	private static final int NODE_COUNT_FOR_COLLAPSING_TREE = 100;

	public enum ActionType {
		COPY, MOVE
	}

	private DataTypeArchiveGTree gTree;
	private GTreeNode destinationNode;
	private List<GTreeNode> droppedNodes;
	private Archive sourceArchive;
	private Archive destinationArchive;

	private ActionType actionType;
	private DataTypeConflictHandler conflictHandler;
	private List<String> errors = new ArrayList<>();

	// for testing
	DataTypeTreeCopyMoveTask() {
		super("Drag/Drop", true, true, true);
	}

	public DataTypeTreeCopyMoveTask(GTreeNode destinationNode, List<GTreeNode> droppedNodeList,
			ActionType actionType, DataTypeArchiveGTree gTree,
			DataTypeConflictHandler conflictHandler) {
		super("Drag/Drop", true, true, true);
		this.destinationNode = destinationNode;
		this.droppedNodes = droppedNodeList;
		this.actionType = actionType;
		this.gTree = gTree;
		this.conflictHandler = conflictHandler;
		this.destinationArchive = findArchive(destinationNode);

		GTreeNode firstNode = droppedNodes.get(0);
		this.sourceArchive = findArchive(firstNode);
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

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		int nodeCount = droppedNodes.size();
		filterRedundantNodes();

		if (checkForDifferentSourceArchives()) {
			return;
		}

		//
		// Note: we collapse the node before performing this work because there is a 
		//       potential for a large number of events to be generated.  Further, if the
		//       given archive node has many children (like 10s of thousands), then the
		//       copious events generated herein could lock the UI.  By closing the node, 
		//       the tree is not invalidating/validating its cache as a result of these
		//       events.
		//
		GTreeState treeState = gTree.getTreeState();
		try {
			if (nodeCount > NODE_COUNT_FOR_COLLAPSING_TREE) {
				collapseArchives();
			}

			if (needToCreateAssociation()) {
				associateDataTypes(monitor);
			}

			doCopy(monitor);

		}
		catch (CancelledException e) {
			return; // nothing to report
		}
		finally {
			gTree.restoreTreeState(treeState);
		}

		reportErrors();
	}

	private void reportErrors() {
		if (errors.isEmpty()) {
			return;
		}

		String message = errors.get(0);
		int n = errors.size();
		if (n > 1) {
			message = "Encountered " + n + " errors copying/moving.  See the log for details";
		}

		Msg.showError(this, gTree, "Encountered Errors Copying/Moving", message);
	}

	private boolean checkForDifferentSourceArchives() {

		for (GTreeNode node : droppedNodes) {
			if (sourceArchive != findArchive(node)) {
				Msg.showError(this, gTree, "Copy Failed",
					"All dragged data types must be from the same archive!");
				return true;
			}
		}

		return false;
	}

	private void doCopy(TaskMonitor monitor) {
		DataTypeManager dtm = destinationArchive.getDataTypeManager();
		int txId = dtm.startTransaction("Copy/Move Category/DataType");
		try {
			if (destinationNode instanceof DataTypeNode) {
				dragNodeToDataType();
			}
			else {
				dragNodesToCategory(monitor);
			}
		}
		finally {
			dtm.endTransaction(txId, true);
		}
	}

	private boolean needToCreateAssociation() {

		// copying from the program archive into another archive
		return sourceArchive != destinationArchive &&
			!(destinationArchive instanceof ProgramArchive) &&
			(sourceArchive instanceof ProgramArchive);
	}

	private void collapseArchives() {
		GTreeNode root = gTree.getModelRoot();
		List<GTreeNode> children = root.getChildren();
		for (GTreeNode archive : children) {
			gTree.collapseAll(archive);
		}
	}

	private void associateDataTypes(TaskMonitor monitor)
			throws CancelledException {

		if (!promptToAssociateTypes(monitor)) {
			return;
		}

		monitor.initialize(droppedNodes.size());

		SourceArchive destination = destinationArchive.getDataTypeManager().getLocalSourceArchive();
		DataTypeManager dtm = sourceArchive.getDataTypeManager();
		int txId = dtm.startTransaction("Associate DataTypes");
		try {
			for (GTreeNode node : droppedNodes) {
				monitor.checkCanceled();

				if (node instanceof DataTypeNode) {
					DataType dt = ((DataTypeNode) node).getDataType();
					associateDataType(dt, dtm, destination);
				}
				else if (node instanceof CategoryNode) {
					Category cat = ((CategoryNode) node).getCategory();
					associateDataTypes(cat, dtm, destination);
				}

				monitor.incrementProgress(1);
			}
		}
		finally {
			dtm.endTransaction(txId, true);
		}
	}

	private boolean promptToAssociateTypes(TaskMonitor monitor) throws CancelledException {

		if (!containsUnassociatedTypes(monitor)) {
			return false; // nothing to associate
		}

		int result = askToAssociateDataTypes();
		if (result == OptionDialog.CANCEL_OPTION) {
			throw new CancelledException();
		}

		return result == OptionDialog.YES_OPTION;
	}

	private boolean containsUnassociatedTypes(TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Checking for types to associate");
		monitor.initialize(droppedNodes.size());
		for (GTreeNode node : droppedNodes) {
			monitor.checkCanceled();

			if (node instanceof DataTypeNode) {
				DataType dt = ((DataTypeNode) node).getDataType();
				if (isLocal(dt)) {
					return true; // local means it is not associated
				}
			}
			else if (node instanceof CategoryNode) {
				if (containsUnassociatedTypes(((CategoryNode) node).getCategory(), monitor)) {
					return true;
				}
			}

			monitor.incrementProgress(1);
		}

		return false;
	}

	private boolean containsUnassociatedTypes(Category cat, TaskMonitor monitor)
			throws CancelledException {

		DataType[] types = cat.getDataTypes();
		for (DataType dt : types) {
			monitor.checkCanceled();
			if (isLocal(dt)) {
				return true; // local means it is not associated
			}
		}

		Category[] categories = cat.getCategories();
		for (Category child : categories) {
			monitor.checkCanceled();
			if (containsUnassociatedTypes(child, monitor)) {
				return true;
			}
		}

		return false;
	}

	private void associateDataType(DataType dt, DataTypeManager dtm, SourceArchive source) {

		if (!isLocal(dt)) {
			return; // not local means it is already associated
		}

		dtm.associateDataTypeWithArchive(dt, source);
	}

	private void associateDataTypes(Category cat, DataTypeManager dtm, SourceArchive destination) {

		DataType[] dataTypes = cat.getDataTypes();
		for (DataType dataType : dataTypes) {
			associateDataType(dataType, dtm, destination);
		}

		Category[] categories = cat.getCategories();
		for (Category category : categories) {
			associateDataTypes(category, dtm, destination);
		}
	}

	private void dragNodesToCategory(TaskMonitor monitor) {

		monitor.setMessage("Drag/Drop Categories/Data Types");
		monitor.initialize(droppedNodes.size());

		Category toCategory = getCategory(destinationNode);
		for (GTreeNode node : droppedNodes) {
			if (monitor.isCancelled()) {
				break;
			}

			monitor.setMessage("Adding " + node.getName());

			// COPY is only allowed action if the source and destination archives are different.
			if (actionType == ActionType.COPY || sourceArchive != destinationArchive) {
				copyNode(toCategory, node, monitor);
			}
			else {
				moveNode(toCategory, node, monitor);
			}

			monitor.incrementProgress(1);
		}
	}

	private void copyNode(Category toCategory, GTreeNode node, TaskMonitor monitor) {
		if (node instanceof DataTypeNode) {
			DataType nodeDt = ((DataTypeNode) node).getDataType();
			copyDataType(toCategory, nodeDt);
		}
		else if (node instanceof CategoryNode) {
			Category category = ((CategoryNode) node).getCategory();
			copyCategory(toCategory, category, monitor);
		}
	}

	private void copyDataType(Category toCategory, DataType dataType) {

		DataTypeManager dtm = toCategory.getDataTypeManager();
		DataTypeManager nodeDtm = dataType.getDataTypeManager();
		boolean sameManager = (dtm == nodeDtm);
		DataType newDt = !sameManager ? dataType.clone(nodeDtm) : dataType.copy(nodeDtm);
		if (sameManager &&
			newDt.getCategoryPath().equals(toCategory.getCategoryPath())) {
			renameAsCopy(toCategory, newDt);
		}

		DataType resolvedDt = toCategory.addDataType(newDt, conflictHandler);
		if (resolvedDt instanceof Pointer || resolvedDt instanceof Array ||
			resolvedDt instanceof BuiltInDataType ||
			resolvedDt instanceof MissingBuiltInDataType) {
			return;
		}

		if (!resolvedDt.getCategoryPath().equals(toCategory.getCategoryPath())) {
			errors.add(
				"Data type copy failed.  Another copy of this data type already exists at " +
					resolvedDt.getPathName());
		}
	}

	private void renameAsCopy(Category destinationCategory, DataType dataType) {
		String dtName = dataType.getName();
		String baseName = getBaseName(dtName);
		String copyName = getNextCopyName(destinationCategory, baseName);
		try {
			dataType.setName(copyName);
		}
		catch (DuplicateNameException | InvalidNameException e) {
			errors.add("Problem creating copy of " + baseName + ". " + e.getMessage());
		}
	}

	String getBaseName(String dtName) {

		// format: Copy_of_foobar
		//         Copy_2_of_foobar
		Pattern p = Pattern.compile("Copy_(?:\\d+_)*of_(.*)");
		Matcher matcher = p.matcher(dtName);
		if (!matcher.matches()) {
			return dtName;
		}

		String baseName = matcher.group(1);
		return baseName;
	}

	String getNextCopyName(Category destinationCategory, String baseName) {

		String format = "Copy_%d_of_" + baseName;
		for (int i = 1; i < 100; i++) {
			String copyName = String.format(format, i);
			if (destinationCategory.getDataType(copyName) == null) {
				return copyName;
			}
		}

		// should never happen; do something reasonable
		return String.format(format, System.currentTimeMillis());
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

	private void moveCategory(Category toCategory, Category category,
			TaskMonitor monitor) {
		if (category.getParent() == toCategory) { // moving to same place
			return;
		}
		try {
			CategoryPath path = toCategory.getCategoryPath();
			if (path.isAncestorOrSelf(category.getCategoryPath())) {
				errors.add(
					"Cannot move a parent node onto a child node.  Moving " + category + " to " +
						toCategory);
				return;
			}

			toCategory.moveCategory(category, monitor);
		}
		catch (DuplicateNameException e) {
			errors.add("Move failed due to duplicate name.   Moving " + category + " to " +
				toCategory + ": " + e.getMessage());
		}
	}

	private void moveDataType(Category toCategory, DataType dataType) {
		if (dataType.getCategoryPath().equals(toCategory.getCategoryPath())) {
			errors.add(
				"Move failed.  DataType is already in this category.  Category " + toCategory +
					"; Data type: " + dataType);
			return;
		}
		try {
			toCategory.moveDataType(dataType, conflictHandler);
		}
		catch (DataTypeDependencyException e) {
			errors.add(
				"Move failed.  DataType is already in this category.  Category " + toCategory +
					"; Data type: " + dataType + ". " + e.getMessage());
		}
	}

	private void copyCategory(Category toCategory, Category category,
			TaskMonitor monitor) {
		CategoryPath toPath = toCategory.getCategoryPath();
		boolean sameManager =
			(toCategory.getDataTypeManager() == category.getDataTypeManager());
		if (sameManager && toPath.isAncestorOrSelf(category.getCategoryPath())) {
			errors.add("Copy failed.  " +
				"Cannot copy a parent node onto a child node. Moving " + category + " to " +
				toCategory);
			return;
		}
		toCategory.copyCategory(category, conflictHandler, monitor);
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

	private boolean isAssociatedEitherWay(DataType dt1, DataType dt2) {
		return isAssociated(dt1, dt2) || isAssociated(dt2, dt1);
	}

	private boolean isAssociated(DataType sourceDt, DataType destinationDt) {
		UniversalID destinationID = destinationDt.getUniversalID();
		if (destinationID == null || !destinationID.equals(sourceDt.getUniversalID())) {
			return false;
		}
		if (!haveSameSourceArchive(sourceDt, destinationDt)) {
			return false;
		}
		return isLocal(sourceDt);
	}

	private boolean haveSameSourceArchive(DataType dt1, DataType dt2) {
		SourceArchive s1 = dt1.getSourceArchive();
		SourceArchive s2 = dt2.getSourceArchive();
		return s1.getSourceArchiveID().equals(s2.getSourceArchiveID());
	}

	/**
	 * Returns true if the given data type's source archive is the same as it's current data
	 * type manager.  This is false if copying a new type from the program to an 
	 * external archive.  
	 * 
	 * @param dt the type
	 * @return true if the given type already lives in its source archive
	 */
	private boolean isLocal(DataType dt) {
		UniversalID sourceId = dt.getSourceArchive().getSourceArchiveID();
		UniversalID dtmId = dt.getDataTypeManager().getUniversalID();
		return sourceId.equals(dtmId);
	}

	private void dragNodeToDataType() {
		DataType destinationDt = ((DataTypeNode) destinationNode).getDataType();

		// there must be exactly one and it must be a dataTypeNode, because of isValidDropSite()
		GTreeNode node = droppedNodes.get(0);
		DataType replacementDt = ((DataTypeNode) node).getDataType();
		if (sourceArchive != destinationArchive) {
			if (isAssociatedEitherWay(replacementDt, destinationDt)) {
				handleAssociatedType(destinationDt, replacementDt);
				return;
			}

			replacementDt = replacementDt.clone(replacementDt.getDataTypeManager());
		}
		else if (actionType == ActionType.COPY) { // Copy within a single data type manager.
			replacementDt = replacementDt.copy(replacementDt.getDataTypeManager());
		}

		replaceDataType(destinationDt, replacementDt);
	}

	private void handleAssociatedType(DataType destinationDt, DataType replacementDt) {
		if (isLocal(destinationDt)) {
			DataTypeSyncInfo syncInfo = new DataTypeSyncInfo(replacementDt,
				destinationDt.getDataTypeManager());
			if (!syncInfo.canCommit()) {
				Msg.showInfo(getClass(), gTree, "Commit Data Type",
					"No changes to commit");
			}
			// destination data-type is local to an archive
			else if (confirmCommit()) {
				// if the destination dataType is local to its dataTypeManager 
				// then we are committing.
				DataTypeSynchronizer.commit(destinationDt.getDataTypeManager(), replacementDt);
			}
		}
		else { // else we are updating
			DataTypeSyncInfo syncInfo = new DataTypeSyncInfo(destinationDt,
				replacementDt.getDataTypeManager());
			if (!syncInfo.canUpdate()) {
				Msg.showInfo(getClass(), gTree, "Update Data Type", "No changes to copy");
			}
			else if (confirmUpdate()) {
				DataTypeSynchronizer.update(destinationDt.getDataTypeManager(), replacementDt);
			}
		}
	}

	private boolean confirmCommit() {
		return confirm("Commit Data Type?",
			"Do you want to commit the changes to this data type back to the source Archive? \n" +
				"(Warning: any changes in the source archive will be overwritten.)");
	}

	private boolean confirmUpdate() {
		return confirm("Update Data Type?",
			"Do you want to update this data type with the changes in the source Archive?\n" +
				"(Warning: any local changes will be overwritten.)");
	}

	private boolean confirm(String title, String message) {
		int choice = OptionDialog.showYesNoDialog(gTree, title, message);
		return choice == OptionDialog.YES_OPTION;
	}

	private int askToAssociateDataTypes() {
		return OptionDialog.showYesNoCancelDialog(gTree, "Associate DataTypes?",
			"Do you want to associate local datatypes with the target archive?");
	}

	private void replaceDataType(DataType existingDt, DataType replacementDt) {

		int choice =
			OptionDialog.showYesNoDialog(gTree, "Replace Data Type?", "Replace " +
				existingDt.getPathName() + "\nwith " + replacementDt.getPathName() +
				"?");

		if (choice == OptionDialog.YES_OPTION) {
			try {
				DataTypeManager dtMgr = existingDt.getDataTypeManager();
				dtMgr.replaceDataType(existingDt, replacementDt, true);
			}
			catch (DataTypeDependencyException e) {
				errors.add("Replace failed.  Existing type " + existingDt + "; replacment type " +
					replacementDt + ". " + e.getMessage());
			}
		}
	}

	// filters out nodes with categories in their path 
	private void filterRedundantNodes() {

		Set<GTreeNode> nodeSet = new HashSet<>(droppedNodes);
		List<GTreeNode> filteredList = new ArrayList<>();

		for (GTreeNode node : nodeSet) {
			if (!containsAncestor(nodeSet, node)) {
				filteredList.add(node);
			}
		}

		droppedNodes = filteredList;
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
