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
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.ProgramArchive;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for copying and moving data type nodes within the Data Types tree.
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
	private Category destinationCategory;
	private List<GTreeNode> copyMoveNodes;
	private Archive sourceArchive;
	private Archive destinationArchive;
	private boolean promptToAssociateTypes = true;
	private ActionType actionType;
	private DataTypeConflictHandler conflictHandler;
	private List<String> errors = new ArrayList<>();

	// for testing
	DataTypeTreeCopyMoveTask() {
		super("Drag/Drop", true, true, true);
	}

	public DataTypeTreeCopyMoveTask(CategoryNode destinationNode, List<GTreeNode> droppedNodeList,
			ActionType actionType, DataTypeArchiveGTree gTree,
			DataTypeConflictHandler conflictHandler) {
		this(findArchive(destinationNode), destinationNode.getCategory(), droppedNodeList,
			actionType, gTree, conflictHandler);
	}

	public DataTypeTreeCopyMoveTask(Archive destinationArchive, Category destinationCategory,
			List<GTreeNode> droppedNodeList, ActionType actionType, DataTypeArchiveGTree gTree,
			DataTypeConflictHandler conflictHandler) {
		super("Drag/Drop", true, true, true);
		this.destinationCategory = destinationCategory;
		this.copyMoveNodes = droppedNodeList;
		this.actionType = actionType;
		this.gTree = gTree;
		this.conflictHandler = conflictHandler;
		this.destinationArchive = destinationArchive;

		GTreeNode firstNode = copyMoveNodes.get(0);
		this.sourceArchive = findArchive(firstNode);
	}

	private static Archive findArchive(GTreeNode node) {
		while (node != null) {
			if (node instanceof ArchiveNode) {
				return ((ArchiveNode) node).getArchive();
			}
			node = node.getParent();
		}
		return null;
	}

	/**
	 * Any types being newly copied/moved to a suitable archive are eligible for 'association',
	 * which means changes between the two archives will be tracked.  True, the default, signals to
	 * prompt before associating types; false signals not to prompt the user, but to always
	 * associate types.
	 *
	 * @param prompt true to prompt; false to not prompt
	 */
	public void setPromptToAssociateTypes(boolean prompt) {
		this.promptToAssociateTypes = prompt;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		int nodeCount = copyMoveNodes.size();
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

		for (GTreeNode node : copyMoveNodes) {
			if (sourceArchive != findArchive(node)) {
				Msg.showError(this, gTree, "Copy Failed",
					"All data types must be from the same archive!");
				return true;
			}
		}

		return false;
	}

	private void doCopy(TaskMonitor monitor) {
		DataTypeManager dtm = destinationArchive.getDataTypeManager();
		int txId = dtm.startTransaction("Copy/Move Category/DataType");
		try {
			copyOrMoveNodesToCategory(monitor);
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

	private void associateDataTypes(TaskMonitor monitor) throws CancelledException {

		if (!promptToAssociateTypes(monitor)) {
			return;
		}

		monitor.initialize(copyMoveNodes.size());

		SourceArchive destination = destinationArchive.getDataTypeManager().getLocalSourceArchive();
		DataTypeManager dtm = sourceArchive.getDataTypeManager();
		int txId = dtm.startTransaction("Associate Data Types");
		try {
			for (GTreeNode node : copyMoveNodes) {
				monitor.checkCancelled();

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

		if (!promptToAssociateTypes) {
			return true; // do not prompt; always associate
		}

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
		monitor.initialize(copyMoveNodes.size());
		for (GTreeNode node : copyMoveNodes) {
			monitor.checkCancelled();

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
			monitor.checkCancelled();
			if (isLocal(dt)) {
				return true; // local means it is not associated
			}
		}

		Category[] categories = cat.getCategories();
		for (Category child : categories) {
			monitor.checkCancelled();
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

	private void copyOrMoveNodesToCategory(TaskMonitor monitor) {

		monitor.setMessage("Drag/Drop Categories/Data Types");
		monitor.initialize(copyMoveNodes.size());

		Category toCategory = destinationCategory;
		for (GTreeNode node : copyMoveNodes) {
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

		if (!sameManager && toCategory.isRoot()) {
			// preserve use of source category when copy to root
			toCategory = dtm.createCategory(dataType.getCategoryPath());
		}

		if (sameManager && newDt.getCategoryPath().equals(toCategory.getCategoryPath())) {
			renameAsCopy(toCategory, newDt);
		}

		DataType resolvedDt = toCategory.addDataType(newDt, conflictHandler);
		if (resolvedDt instanceof Pointer || resolvedDt instanceof Array ||
			resolvedDt instanceof BuiltInDataType || resolvedDt instanceof MissingBuiltInDataType) {
			return;
		}

		if (!resolvedDt.getCategoryPath().equals(toCategory.getCategoryPath())) {
			errors.add("Data type copy failed.  Another copy of this data type already exists at " +
				resolvedDt.getPathName());
		}
	}

	private void renameAsCopy(Category toCategory, DataType dataType) {
		String dtName = dataType.getName();
		String baseName = getBaseName(dtName);
		String copyName = getNextCopyName(toCategory, baseName);
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

	String getNextCopyName(Category toCategory, String baseName) {

		String format = "Copy_%d_of_" + baseName;
		for (int i = 1; i < 100; i++) {
			String copyName = String.format(format, i);
			if (toCategory.getDataType(copyName) == null) {
				return copyName;
			}
		}

		// should never happen; do something reasonable
		return String.format(format, System.currentTimeMillis());
	}

	private void moveNode(Category toCategory, GTreeNode node, TaskMonitor monitor) {
		if (node instanceof DataTypeNode) {
			DataType dataType = ((DataTypeNode) node).getDataType();
			moveDataType(toCategory, dataType);
		}
		else if (node instanceof CategoryNode) {
			Category category = ((CategoryNode) node).getCategory();
			moveCategory(toCategory, category, monitor);
		}
	}

	private void moveCategory(Category toCategory, Category category, TaskMonitor monitor) {
		if (category.getParent() == toCategory) { // moving to same place
			return;
		}
		try {
			CategoryPath path = toCategory.getCategoryPath();
			if (path.isAncestorOrSelf(category.getCategoryPath())) {
				errors.add("Cannot move a parent node onto a child node.  Moving " + category +
					" to " + toCategory);
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
			errors.add("Move failed.  DataType is already in this category.  Category " +
				toCategory + "; Data type: " + dataType.getName());
			return;
		}
		try {
			toCategory.moveDataType(dataType, conflictHandler);
		}
		catch (DataTypeDependencyException e) {
			errors.add("Move failed.  DataType is already in this category.  Category " +
				toCategory + "; Data type: " + dataType.getName() + ". " + e.getMessage());
		}
	}

	private void copyCategory(Category toCategory, Category category, TaskMonitor monitor) {
		CategoryPath toPath = toCategory.getCategoryPath();
		boolean sameManager = (toCategory.getDataTypeManager() == category.getDataTypeManager());
		if (sameManager && toPath.isAncestorOrSelf(category.getCategoryPath())) {
			errors.add("Copy failed.  " + "Cannot copy a parent node onto a child node. Moving " +
				category + " to " + toCategory);
			return;
		}
		toCategory.copyCategory(category, conflictHandler, monitor);
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

	private int askToAssociateDataTypes() {
		return OptionDialog.showYesNoCancelDialog(gTree, "Associate Data Types?",
			"Do you want to associate local data types with the target archive?");
	}

	// filters out nodes with categories in their path
	private void filterRedundantNodes() {

		Set<GTreeNode> nodeSet = new HashSet<>(copyMoveNodes);
		List<GTreeNode> filteredList = new ArrayList<>();

		for (GTreeNode node : nodeSet) {
			if (!containsAncestor(nodeSet, node)) {
				filteredList.add(node);
			}
		}

		copyMoveNodes = filteredList;
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
