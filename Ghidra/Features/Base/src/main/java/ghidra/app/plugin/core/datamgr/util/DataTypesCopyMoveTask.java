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
import java.util.stream.Collectors;

import docking.widgets.OptionDialog;
import docking.widgets.tree.*;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.tree.CategoryNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.DataTypeStore;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for copying or moving data types and categories between archives in a Data Type Manager 
 * tree.
 */
public class DataTypesCopyMoveTask extends Task {

	// If the total number of nodes is small, we won't need to collapse the tree before deleting
	// the nodes to avoid excess tree events.  This number is very arbitrary.  This number is
	// used to compare the number of dragged nodes, which may include categories whose child
	// count is not reflected in this number.  This could mean that thousands of nodes will be
	// processed, but the actual drag count could be much less.
	private static final int NODE_COUNT_FOR_COLLAPSING_TREE = 100;

	public enum ActionType {
		COPY, MOVE
	}

	private GTree tree;
	private DataTypeStore sourceStore;
	private DataTypeStore destinationStore;
	private Category destinationCategory;
	private List<DataType> types;
	private List<Category> categories;
	private int count;
	private DataTypeConflictHandler conflictHandler;

	private ActionType actionType;
	private boolean promptToAssociateTypes = true;

	private List<String> errors = new ArrayList<>();

	/**
	 * Constructor method for creating a task from category and data type nodes.  This is used when
	 * using drag-n-drop.
	 * 
	 * @param plugin the plugin
	 * @param tree the primary provider's tree or a snapshot
	 * @param destination the destination category
	 * @param nodes the nodes being dropped
	 * @param actionType the action type
	 * @return the new task
	 */
	public static DataTypesCopyMoveTask forNodes(DataTypeManagerPlugin plugin, GTree tree,
			Category destination, List<GTreeNode> nodes, ActionType actionType) {

		List<Category> categories = new ArrayList<>();
		List<DataType> types = new ArrayList<>();
		convertNodes(nodes, categories, types);

		DataTypesCopyMoveTask task =
			new DataTypesCopyMoveTask(plugin, destination, types, categories, actionType);
		task.tree = tree;
		return task;
	}

	private static void convertNodes(List<GTreeNode> nodes, List<Category> categories,
			List<DataType> types) {

		for (GTreeNode node : nodes) {
			if (node instanceof CategoryNode catNode) {
				categories.add(catNode.getCategory());
			}
			else if (node instanceof DataTypeNode dtNode) {
				types.add(dtNode.getDataType());
			}
		}
	}

	private DataTypesCopyMoveTask(DataTypeManagerPlugin plugin, Category destinationCategory,
			List<DataType> types, List<Category> categories, ActionType actionType) {

		super("Drag/Drop Data Types", true, true, true);
		this.destinationCategory = destinationCategory;
		this.types = types == null ? List.of() : types;
		this.categories = categories == null ? List.of() : categories;
		this.actionType = actionType;
		this.tree = plugin.getProvider().getGTree();
		this.conflictHandler = plugin.getConflictHandler();

		DataTypeManager destDtm = destinationCategory.getDataTypeManager();
		this.destinationStore = destDtm.getDataStore();

		this.count = types.size() + categories.size();
	}

	public DataTypesCopyMoveTask(DataTypeManagerPlugin plugin, DataTypeStore destinationArchive,
			Category destinationCategory, List<DataType> types, List<Category> categories,
			ActionType actionType) {

		super("Drag/Drop Data Types", true, true, true);
		this.destinationCategory = destinationCategory;
		this.types = types == null ? List.of() : types;
		this.categories = categories == null ? List.of() : categories;
		this.actionType = actionType;
		this.tree = plugin.getProvider().getGTree();
		this.conflictHandler = plugin.getConflictHandler();
		this.destinationStore = destinationArchive;

		this.count = this.types.size() + this.categories.size();
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

		filterRedundantTypes();

		//
		// Note: we collapse the node before performing this work because there is a
		//       potential for a large number of events to be generated.  Further, if the
		//       given archive node has many children (like 10s of thousands), then the
		//       copious events generated herein could lock the UI.  By closing the node,
		//       the tree is not invalidating/validating its cache as a result of these
		//       events.
		//
		GTreeState treeState = tree.getTreeState();
		try {

			sourceStore = getSourceStore(monitor);

			if (count > NODE_COUNT_FOR_COLLAPSING_TREE) {
				collapseArchives();
			}

			if (needToCreateAssociation()) {

				// Warning! (See GP-6367): association should not really be made before copy
				// which may return an equivalent datatype with the same name and category path
				// and a different UniversalID. This condition results in an ORPHANed association.

				// NOTE: The resulting copied datatype may end up with a different name due to a
				// conflict (same UniversalID).  This name difference will persist without apparent 
				// impact to the association or anyway to know this is the case.

				associateDataTypes(monitor);
			}

			doCopy(monitor);
		}
		catch (CancelledException e) {
			return; // nothing to report
		}
		finally {
			tree.restoreTreeState(treeState);
		}

		reportErrors();
	}

	private DataTypeStore getSourceStore(TaskMonitor monitor) throws CancelledException {

		DataTypeStore firstStore = null;

		for (Category category : categories) {
			monitor.checkCancelled();
			DataTypeManager dtm = category.getDataTypeManager();
			DataTypeStore archive = dtm.getDataStore();
			if (firstStore == null) {
				firstStore = archive;
				continue;
			}

			if (firstStore != archive) {
				Msg.showError(this, tree, "Copy Failed",
					"All data types must be from the same archive!");
				throw new CancelledException();
			}
		}

		for (DataType dt : types) {
			monitor.checkCancelled();
			DataTypeManager dtm = dt.getDataTypeManager();
			DataTypeStore archive = dtm.getDataStore();
			if (firstStore == null) {
				firstStore = archive;
				continue;
			}

			if (firstStore != archive) {
				Msg.showError(this, tree, "Copy Failed",
					"All data types must be from the same archive!");
				throw new CancelledException();
			}
		}

		return firstStore;
	}

	private void reportErrors() {
		if (errors.isEmpty()) {
			return;
		}

		String message = errors.get(0);
		int n = errors.size();
		if (n > 1) {
			message = "Encountered " + n + " errors copying/moving.  See the log for details";

			int max = n < 10 ? n : 10;
			for (int i = 0; i < max; i++) {
				Msg.error(this, errors.get(i));
			}
		}

		Msg.showError(this, tree, "Encountered Errors Copying/Moving", message);
	}

	private void doCopy(TaskMonitor monitor) throws CancelledException {
		DataTypeManager dtm = destinationStore.getDataTypeManager();
		dtm.withTransaction("Copy/Move Category/DataType", () -> {
			copyOrMoveNodesToCategory(monitor);
		});
	}

	private boolean needToCreateAssociation() {

		// copying from the program archive into another archive
		return sourceStore != destinationStore &&
			!(destinationStore instanceof Program) &&
			(sourceStore instanceof Program);
	}

	private void collapseArchives() {
		GTreeNode root = tree.getModelRoot();
		List<GTreeNode> children = root.getChildren();
		for (GTreeNode archive : children) {
			tree.collapseAll(archive);
		}
	}

	private void associateDataTypes(TaskMonitor monitor) throws CancelledException {

		if (!promptToAssociateTypes(monitor)) {
			return;
		}

		monitor.initialize(count);

		DataTypeManager destionationDtm = destinationStore.getDataTypeManager();
		SourceArchive destination = destionationDtm.getLocalSourceArchive();
		DataTypeManager sourceDtm = sourceStore.getDataTypeManager();
		sourceDtm.withTransaction("Associate Data Types", () -> {

			for (Category cat : categories) {
				associateDataTypes(cat, sourceDtm, destination);
				monitor.increment();
			}

			for (DataType dt : types) {
				associateDataType(dt, sourceDtm, destination);
				monitor.increment();
			}
		});
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
		monitor.initialize(count);

		for (Category cat : categories) {
			if (containsUnassociatedTypes(cat, monitor)) {
				return true;
			}
			monitor.increment();
		}

		for (DataType dt : types) {
			if (isLocal(dt)) {
				return true;
			}
			monitor.increment();
		}

		return false;
	}

	private boolean containsUnassociatedTypes(Category cat, TaskMonitor monitor)
			throws CancelledException {

		DataType[] catTypes = cat.getDataTypes();
		for (DataType dt : catTypes) {
			monitor.checkCancelled();
			if (isLocal(dt)) {
				return true; // local means it is not associated
			}
		}

		Category[] subCats = cat.getCategories();
		for (Category child : subCats) {
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

		Category[] subCats = cat.getCategories();
		for (Category category : subCats) {
			associateDataTypes(category, dtm, destination);
		}
	}

	private void copyOrMoveNodesToCategory(TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Drag/Drop Categories/Data Types");
		monitor.initialize(count);

		Category toCategory = destinationCategory;

		for (Category cat : categories) {
			monitor.setMessage("Adding " + cat.getName());

			// COPY is only allowed action if the source and destination archives are different.
			if (actionType == ActionType.COPY || sourceStore != destinationStore) {
				copyCategory(toCategory, cat, monitor);
			}
			else {
				moveCategory(toCategory, cat, monitor);
			}

			monitor.increment();
		}

		for (DataType dt : types) {
			monitor.setMessage("Adding " + dt.getName());

			// COPY is only allowed action if the source and destination archives are different.
			if (actionType == ActionType.COPY || sourceStore != destinationStore) {
				copyDataType(toCategory, dt);
			}
			else {
				moveDataType(toCategory, dt);
			}

			monitor.increment();
		}
	}

	private void copyDataType(Category toCategory, DataType dataType) {

		DataTypeManager dtm = toCategory.getDataTypeManager();
		DataTypeManager nodeDtm = dataType.getDataTypeManager();
		boolean sameManager = (dtm == nodeDtm);

		DataType newDt = !sameManager ? dataType : dataType.copy(nodeDtm);

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

	static String getBaseName(String dtName) {

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

	static String getNextCopyName(Category toCategory, String baseName) {

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

	private void moveCategory(Category toCategory, Category category, TaskMonitor monitor) {
		if (category.getParent() == toCategory) { // // moving to same place	return;
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
		return OptionDialog.showYesNoCancelDialog(tree, "Associate Data Types?",
			"Do you want to associate local data types with the target archive?");
	}

	// filters out nodes with categories in their path
	private void filterRedundantTypes() {

		Set<Category> set = new HashSet<>();
		set.addAll(categories);

		List<Category> filteredCats =
			categories.stream()
					.filter(c -> !containsAncestor(set, c))
					.collect(Collectors.toList());

		List<DataType> filteredTypes =
			types.stream()
					.filter(dt -> !containsAncestor(set, dt))
					.collect(Collectors.toList());

		categories = filteredCats;
		types = filteredTypes;
	}

	private Category getCategory(DataType dt) {
		CategoryPath path = dt.getCategoryPath();
		DataTypeManager dtm = dt.getDataTypeManager();
		return dtm.getCategory(path);
	}

	private boolean containsAncestor(Set<Category> set, Category cat) {

		Category parent = cat.getParent();
		if (parent == null) {
			return false;
		}
		if (set.contains(parent)) {
			return true;
		}

		return containsAncestor(set, parent);
	}

	private boolean containsAncestor(Set<Category> set, DataType dt) {
		Category parent = getCategory(dt);
		if (set.contains(parent)) {
			return true;
		}

		return containsAncestor(set, parent);
	}

}
