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
package ghidra.app.merge.datatypes;

import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.SwingUtilities;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.merge.*;
import ghidra.app.util.HelpTopics;
import ghidra.framework.data.DomainObjectMergeManager;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.DataTypeChangeSet;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Manager for merging category and data type changes
 */
public class DataTypeMergeManager implements MergeResolver {

	private static String[] DATA_TYPES_PHASE = new String[] { "Data Types" };
	private static final int RESULT = MergeConstants.RESULT;
	private static final int ORIGINAL = MergeConstants.ORIGINAL;
	private static final int LATEST = MergeConstants.LATEST;
	private static final int MY = MergeConstants.MY;

	// Each of the following is a choice or possible resolution when merging data types.
	static final int CANCELED = -2; // user canceled the merge operation
	static final int ASK_USER = -1;// prompt the user to choose resolution
	static final int OPTION_LATEST = 0; // Latest 
	static final int OPTION_MY = 1; // My change 
	static final int OPTION_ORIGINAL = 2; // Original

	private DomainObjectMergeManager mergeManager;
	private DataTypeManagerDomainObject[] domainObjects = new DataTypeManagerDomainObject[4];
	private DataTypeManager[] dtms = new DataTypeManager[4];
	private TaskMonitor currentMonitor;
	private int originalConflictOption;
	private int conflictOption;
	private HashMap<UniversalID, Boolean> dirtyMap; // Source archive ID maps to dirty flag true in Latest or My.
	private ArrayList<Long> myArchiveAddedList;
	private ArrayList<Long> myArchiveChangeList;
	private ArrayList<Long> archiveConflictList;
	private SourceArchiveMergePanel archiveMergePanel;
	private ArrayList<Long> myCatAddedList;
	private ArrayList<Long> myCatChangeList;
	private ArrayList<Long> catConflictList;
	private CategoryMergePanel catMergePanel;
	private ArrayList<Long> myDtAddedList; // keys for added data types.
	private ArrayList<Long> myDtChangeList; // keys for changed data types (includes deleted).
	private ArrayList<Long> dtConflictList;
	private ArrayList<Long> dtSourceConflictList;
	private ArrayList<Long> origDtConflictList;
	private DataTypeMergePanel dtMergePanel;
	private int totalConflictCount;
	private int currentConflictIndex;

	private MyIdentityHashMap<Long, DataType> myResolvedDts; // maps My data type key -> resolved Data type
	private MyIdentityHashMap<Long, DataType> latestResolvedDts; // maps Latest data type key -> resolved Data type
	private MyIdentityHashMap<Long, DataType> origResolvedDts; // maps Original data type key -> resolved Data type

	private List<FixUpInfo> fixUpList; // FixUpInfo objects that must be resolved after
	private HashSet<Long> fixUpIDSet; // track types with fixups

	private int progressIndex; // index for showing progress

	private int categoryChoice = ASK_USER;
	private int dataTypeChoice = ASK_USER;
	private int sourceArchiveChoice = ASK_USER;

	/**
	 * Manager for merging the data types using the four programs.
	 * @param mergeManager overall merge manager for domain object
	 * @param resultDomainObject the program to be updated with the result of the merge.
	 * This is the program that will actually get checked in.
	 * @param myDomainObject the program requesting to be checked in.
	 * @param originalDomainObject the program that was checked out.
	 * @param latestDomainObject the latest checked-in version of the program.
	 * @param latestChanges the address set of changes between original and latest versioned program.
	 * @param myChanges the address set of changes between original and my modified program.
	 */
	public DataTypeMergeManager(DomainObjectMergeManager mergeManager,
			DataTypeManagerDomainObject resultDomainObject,
			DataTypeManagerDomainObject myDomainObject,
			DataTypeManagerDomainObject originalDomainObject,
			DataTypeManagerDomainObject latestDomainObject, DataTypeChangeSet latestChanges,
			DataTypeChangeSet myChanges) {
		this.mergeManager = mergeManager;
		domainObjects[RESULT] = resultDomainObject;
		domainObjects[ORIGINAL] = originalDomainObject;
		domainObjects[LATEST] = latestDomainObject;
		domainObjects[MY] = myDomainObject;
		dtms[RESULT] = resultDomainObject.getDataTypeManager();
		dtms[ORIGINAL] = originalDomainObject.getDataTypeManager();
		dtms[LATEST] = latestDomainObject.getDataTypeManager();
		dtms[MY] = myDomainObject.getDataTypeManager();

		totalConflictCount = 0;
		setupSourceArchiveChanges(latestChanges, myChanges);
		setupDataTypeChanges(latestChanges, myChanges);
		setupCategoryChanges(latestChanges, myChanges);

		originalConflictOption = ASK_USER;
		conflictOption = ASK_USER;

	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#apply()
	 */
	@Override
	public void apply() {
		if (catMergePanel != null && catMergePanel.isVisible()) {
			conflictOption = catMergePanel.getSelectedOption();
			// If the "Use For All" check box is selected
			// then save the option chosen for this conflict type.
			if (catMergePanel.getUseForAll()) {
				categoryChoice = conflictOption;
			}
		}
		else if (dtMergePanel != null && dtMergePanel.isVisible()) {
			conflictOption = dtMergePanel.getSelectedOption();
			// If the "Use For All" check box is selected
			// then save the option chosen for this conflict type.
			if (dtMergePanel.getUseForAll()) {
				dataTypeChoice = conflictOption;
			}
		}
		else {
			conflictOption = archiveMergePanel.getSelectedOption();
			// If the "Use For All" check box is selected
			// then save the option chosen for this conflict type.
			if (archiveMergePanel.getUseForAll()) {
				sourceArchiveChoice = conflictOption;
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#cancel()
	 */
	@Override
	public void cancel() {
		conflictOption = CANCELED;

	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Merge Data Types and Categories";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getName()
	 */
	@Override
	public String getName() {
		return "Data Type Merger";
	}

	/**
	 * Merge the data types using the four programs.
	 * @param monitor merge task monitor
	 * @see MergeConstants
	 */
	@Override
	public void merge(TaskMonitor monitor) {
		mergeManager.setInProgress(DATA_TYPES_PHASE);
		// For now this method simply does a coarse increment of the progress bar for the current phase.

		this.currentMonitor = monitor;
		monitor.initialize(totalConflictCount + myCatAddedList.size() + myCatChangeList.size() +
			myDtAddedList.size() + myDtChangeList.size());

		int transactionID = domainObjects[RESULT].startTransaction("Merge Categories/Data Types");
		boolean commit = false;
		try {
			mergeManager.updateProgress(0,
				"Data Type Merge is processing changed source archives...");
			processSourceArchiveChanges();

			mergeManager.updateProgress(2,
				"Data Type Merge is processing added source archives...");
			processSourceArchiveAdditions();

			mergeManager.updateProgress(4,
				"Data Type Merge is processing source archive conflicts...");
			processSourceArchiveConflicts();

			mergeManager.updateProgress(6, "Data Type Merge is processing category changes...");
			processCategoryChanges();

			// data types
			mergeManager.updateProgress(12, "Data Type Merge is processing deleted data types...");
			processDataTypesDeleted();

			mergeManager.updateProgress(25, "Data Type Merge is processing added data types...");
			processDataTypesAdded();

			mergeManager.updateProgress(37, "Data Type Merge is processing changed data types...");
			processDataTypeChanges();

			mergeManager.updateProgress(50, "Data Type Merge is processing data type conflicts...");
			processDataTypeConflicts();

			mergeManager.updateProgress(62, "Data Type Merge is processing deleted categories...");
			processCategoriesDeleted();

			mergeManager.updateProgress(75, "Data Type Merge is processing added categories...");
			processCategoriesAdded();

			// process conflicts
			mergeManager.updateProgress(87, "Data Type Merge is processing category conflicts...");
			processCategoryConflicts();

			fixupDirtyFlags();
			mergeManager.updateProgress(100, getDescription());

			if (mergeManager != null) {// may be null in Junits
				mergeManager.setResolveInformation(MergeConstants.RESOLVED_LATEST_DTS,
					latestResolvedDts);
				mergeManager.setResolveInformation(MergeConstants.RESOLVED_MY_DTS, myResolvedDts);
				mergeManager.setResolveInformation(MergeConstants.RESOLVED_ORIGINAL_DTS,
					origResolvedDts);
			}
			commit = true;
		}
		catch (CancelledException e) {
			// User canceled the merge.
		}
		finally {
			domainObjects[RESULT].endTransaction(transactionID, commit);
		}
		mergeManager.setCompleted(DATA_TYPES_PHASE);
	}

	/**
	 * For JUnit testing only, set the option for resolving a conflict.
	 * @param option forced conflict resolution option
	 */
	void setConflictResolution(int option) {
		conflictOption = option;
		originalConflictOption = option;
	}

	private void processSourceArchiveChanges() throws CancelledException {
		conflictOption = OPTION_MY;
		for (Long element : myArchiveChangeList) {
			currentMonitor.checkCancelled();
			currentMonitor.setProgress(++progressIndex);

			long id = element.longValue();

			updateSourceArchive(id);
		}
		resetOption();
	}

	private void updateSourceArchive(long id) {
		UniversalID universalID = new UniversalID(id);
		SourceArchive resultSourceArchive = dtms[RESULT].getSourceArchive(universalID);
		SourceArchive sourceArchive = null;
		int optionToUse = (sourceArchiveChoice == ASK_USER) ? conflictOption : sourceArchiveChoice;
		switch (optionToUse) {
			case OPTION_LATEST:
				return;
			case OPTION_MY:
				sourceArchive = dtms[MY].getSourceArchive(universalID);
				break;
			case OPTION_ORIGINAL:
				sourceArchive = dtms[ORIGINAL].getSourceArchive(universalID);
				break;
			default:
				return;
		}
		if (resultSourceArchive == null) {
			if (sourceArchive != null) {
				addSourceArchive(sourceArchive);
			}
			return;
		}
		if (sourceArchive == null) {
			removeSourceArchive(universalID);
			return;
		}
		updateSourceName(resultSourceArchive, sourceArchive.getName());
		adjustTime(resultSourceArchive, dtms[MY].getSourceArchive(universalID));
	}

	private void updateSourceName(SourceArchive resultSourceArchive, String name) {
		// Name
		if (!resultSourceArchive.getName().equals(name)) {
			resultSourceArchive.setName(name);
		}
	}

	private void processSourceArchiveAdditions() throws CancelledException {
		for (Long element : myArchiveAddedList) {
			currentMonitor.checkCancelled();
			currentMonitor.setProgress(++progressIndex);

			long id = element.longValue();

			UniversalID universalID = new UniversalID(id);
			SourceArchive mySourceArchive = dtms[MY].getSourceArchive(universalID);
			addSourceArchive(mySourceArchive);
		}
	}

	private void addSourceArchive(SourceArchive mySourceArchive) {
		// Latest may have added it with same name so check for existing.
		SourceArchive resultSourceArchive =
			dtms[RESULT].getSourceArchive(mySourceArchive.getSourceArchiveID());
		if (resultSourceArchive != null) {
			adjustTime(resultSourceArchive, mySourceArchive);
			return;
		}
		// If no existing source archive then add My.
		((DataTypeManagerDB) dtms[RESULT]).resolveSourceArchive(mySourceArchive);
	}

	private void removeSourceArchive(UniversalID universalID) {
		SourceArchive resultSourceArchive = dtms[RESULT].getSourceArchive(universalID);
		if (resultSourceArchive == null) {
			return;
		}
		((DataTypeManagerDB) dtms[RESULT]).removeSourceArchive(resultSourceArchive);

	}

	private void adjustTime(SourceArchive resultSourceArchive, SourceArchive mySourceArchive) {
		// Adjust the last sync time.
		long resultTime = resultSourceArchive.getLastSyncTime();
		long myTime = mySourceArchive.getLastSyncTime();
		if (myTime > resultTime) {
			resultSourceArchive.setLastSyncTime(myTime);
		}
		// Adjust the dirty flag.
		UniversalID sourceID = mySourceArchive.getSourceArchiveID();
		Boolean dirtyFlagObject = dirtyMap.get(sourceID);
		if (dirtyFlagObject != null) {
			boolean finalDirtyFlag = dirtyFlagObject.booleanValue();
			if (resultSourceArchive.isDirty() != finalDirtyFlag) {
				resultSourceArchive.setDirtyFlag(finalDirtyFlag);
			}
		}
	}

	private void fixupDirtyFlags() {
		for (UniversalID sourceID : dirtyMap.keySet()) {
			boolean isDirty = dirtyMap.get(sourceID).booleanValue();
			SourceArchive sourceArchive = dtms[RESULT].getSourceArchive(sourceID);
			if (sourceArchive.isDirty() != isDirty) {
				sourceArchive.setDirtyFlag(isDirty);
			}
		}
	}

	private void processSourceArchiveConflicts() throws CancelledException {

		for (Long element : archiveConflictList) {
			currentMonitor.checkCancelled();
			currentMonitor.setProgress(++progressIndex);

			long sourceArchiveID = element.longValue();

			++currentConflictIndex;
			handleSourceArchiveConflict(sourceArchiveID, currentConflictIndex);
		}
		archiveConflictList.clear(); // Done with the conflict list.
	}

	private void handleSourceArchiveConflict(long sourceID, int conflictIndex)
			throws CancelledException {

		if (sourceArchiveChoice == ASK_USER && conflictOption == ASK_USER && mergeManager != null) {
			// block until user resolves the conflict
			showArchiveMergePanel(sourceID, conflictIndex);
			if (conflictOption == CANCELED) {
				throw new CancelledException();
			}
		}
		updateSourceArchive(sourceID);
		resetOption();
	}

	/**
	 * Add new categories.
	 * @throws CancelledException if task cancelled
	 */
	private void processCategoriesAdded() throws CancelledException {
		for (Long element : myCatAddedList) {
			currentMonitor.checkCancelled();
			currentMonitor.setProgress(++progressIndex);

			long id = element.longValue();
			Category myCat = dtms[MY].getCategory(id);
			CategoryPath myPath = myCat.getCategoryPath();
			if (dtms[RESULT].containsCategory(myPath)) {
				continue;
			}
			dtms[RESULT].createCategory(myPath);
		}
	}

	/**
	 * Process conflicts for categories.
	 * @throws CancelledException task was cancelled
	 */
	private void processCategoryConflicts() throws CancelledException {

		for (Long element : catConflictList) {
			currentMonitor.checkCancelled();
			currentMonitor.setProgress(++progressIndex);

			long id = element.longValue();

			++currentConflictIndex;
			handleCategoryConflict(id, currentConflictIndex);
		}
		catConflictList.clear(); // Done with the conflict list.
	}

	private void handleCategoryConflict(long id, int conflictIndex) throws CancelledException {

		if (categoryChoice == ASK_USER && conflictOption == ASK_USER && mergeManager != null) {
			// block until user resolves the conflict
			showCategoryMergePanel(id, conflictIndex);
		}
		if (categoryWasRenamed(id, dtms[MY]) || categoryWasMoved(id, dtms[MY])) {
			categoryRenamedOrMoved(id);
		}
		if (dtms[MY].getCategory(id) == null || dtms[LATEST].getCategory(id) == null) {
			categoryDeleted(id);
		}
		resetOption();
	}

	private void processCategoryChanges() throws CancelledException {
		for (Long element : myCatChangeList) {
			currentMonitor.checkCancelled();
			currentMonitor.setProgress(++progressIndex);

			long id = element.longValue();

			processCategoryRenamed(id);
			processCategoryMoved(id);
		}

	}

	private void processCategoriesDeleted() throws CancelledException {
		for (Long element : myCatChangeList) {
			currentMonitor.checkCancelled();

			long id = element.longValue();
			processCategoryDeleted(id);
		}
	}

	private void processDataTypeConflicts() throws CancelledException {
		while (dtConflictList.size() > 0) {
			currentMonitor.checkCancelled();
			currentMonitor.setProgress(++progressIndex);

			long id = dtConflictList.get(0).longValue();
			++currentConflictIndex;
			handleDataTypeConflict(id, currentConflictIndex);
			dtConflictList.remove(Long.valueOf(id));
		}

		fixUpDataTypes();

		showUnresolvedFixups();
	}

	private void showUnresolvedFixups() {
		if (fixUpList.isEmpty()) {
			return;
		}
		int count = 0;
		boolean logOnly = false;
		StringBuffer sb = new StringBuffer();
		sb.append("The following data types failed to properly resolve, possibly due\n" +
			"to missing dependencies (" + fixUpList.size() + " data type failures):\n");
		for (FixUpInfo info : fixUpList) {
			if (!logOnly && count++ == 30) {
				sb.append("List has been truncated.  See log for additional data type failures");
				String msg = sb.toString();
				MergeManager.showBlockingError("Unresolved Data Types and Components", msg);
				logOnly = true;
				sb = new StringBuffer();
				sb.append("Continuation of data type failure listing:\n");
			}

			DataTypeManager dtm = info.getDataTypeManager();
			DataType dt = dtm.getDataType(info.id);
			DataType compDt = dtm.getDataType(info.compID);
			sb.append("   ");
			String kind = getKind(dt);
			if (kind != null) {
				sb.append(kind);
				sb.append(" ");
			}
			sb.append(dt.getDisplayName());
			sb.append(", ");
			if (info.index < 0) {
				if (dt instanceof FunctionDefinition) {
					sb.append("return-type");
				}
				else {
					sb.append("dependency");
				}
			}
			else {
				if (dt instanceof FunctionDefinition) {
					sb.append("param-");
					sb.append(info.index);
				}
				else if (dt instanceof Union) {
					sb.append("component-");
					sb.append(info.index);
				}
				else if (dt instanceof Structure) {
					Structure resultStruct = (Structure) info.ht.get(info.id);
					sb.append("component-");
					sb.append(info.index);
					if (!resultStruct.isPackingEnabled()) {
						sb.append(", offset-");
						sb.append("0x");
						sb.append(Integer.toHexString(info.offset));
					}
				}
				else {
					sb.append("index-"); // unknown use case
					sb.append(info.index);
				}

			}
			sb.append(": ");
			sb.append(compDt.getDisplayName());
			sb.append("\n");
		}

		// TODO: Use display with scrolling message area
		// TODO: Would be could to allow messages to be saved to a file

		if (logOnly) {
			Msg.error(this, sb.toString());
		}
		else {
			String msg = sb.toString();
			MergeManager.showBlockingError("Unresolved Data Types and Components", msg);
		}
	}

	private String getKind(DataType dt) {
		if (dt instanceof Structure) {
			return "Structure";
		}
		if (dt instanceof Union) {
			return "Union";
		}
		if (dt instanceof TypeDef) {
			return "Typedef";
		}
		if (dt instanceof FunctionDefinition) {
			return "Function-Definition";
		}
		if (dt instanceof Enum) {
			return "Enum";
		}
		return null;
	}

	private void handleDataTypeConflict(long id, int conflictIndex) throws CancelledException {

		DataType myDt = dtms[MY].getDataType(id);
		if (dataTypeChoice == ASK_USER && conflictOption == ASK_USER && mergeManager != null) {
			DataType latestDt = dtms[LATEST].getDataType(id);
			DataType origDt = dtms[ORIGINAL].getDataType(id);
			// block until user resolves the conflict
			showDataTypeMergePanel(conflictIndex, latestDt, myDt, origDt);
			if (conflictOption == CANCELED) {
				throw new CancelledException();
			}
		}
		applyDataTypeConflict(id);
		resetOption();
	}

	private void applyDataTypeConflict(long id) {

		boolean dtAdded = false;
		if (dataTypeWasRenamed(id, dtms[MY]) || dataTypeWasMoved(id, dtms[MY])) {
			dtAdded = dataTypeRenamedOrMoved(id);
		}
		if (!dtAdded) {
			boolean myChanged = dataTypeWasChanged(id, dtms[MY]);
			boolean latestChanged = dataTypeWasChanged(id, dtms[LATEST]);
			boolean wasDeleted =
				dataTypeWasDeleted(id, dtms[MY]) || dataTypeWasDeleted(id, dtms[LATEST]);
			if (myChanged || latestChanged || wasDeleted) {
				dataTypeChanged(id);
			}
			boolean sameSource = !dataTypeSourceWasChanged(id, dtms[LATEST], dtms[MY]);
			boolean mySourceChanged = sameSource ? false : dataTypeSourceWasChanged(id, dtms[MY]);
			boolean latestSourceChanged =
				sameSource ? false : dataTypeSourceWasChanged(id, dtms[LATEST]);
			if (mySourceChanged || latestSourceChanged) {
				changeSourceArchive(id);
			}

			// Make sure the change time is updated (even if keeping the Latest version)
			// since a conflict was resolved for the data type.
			DataType resultDt = dtms[RESULT].getDataType(id);
			if (resultDt != null) {
				long timeNow = System.currentTimeMillis();
				resultDt.setLastChangeTime(timeNow);
			}
		}
		if (dtSourceConflictList.contains(id)) {
			setSourceDataType(id);
		}
	}

	private void setSourceDataType(long myID) {

		DataType myDt = dtms[MY].getDataType(myID);
		SourceArchive sourceArchive = myDt.getSourceArchive();
		UniversalID dataTypeID = myDt.getUniversalID();

		int optionToUse = (dataTypeChoice == ASK_USER) ? conflictOption : dataTypeChoice;
		switch (optionToUse) {
			case OPTION_LATEST:
				// Latest is what we already have.
				break;
			case OPTION_MY:
				// Replace Latest with My data type
				DataType latestDt = dtms[RESULT].getDataType(sourceArchive, dataTypeID);
				long resultID = dtms[RESULT].getID(latestDt);
				DataType resultDt;
				try {
					resultDt = dtms[RESULT].replaceDataType(latestDt, myDt, false);
					CategoryPath myCategoryPath = myDt.getCategoryPath();
					if (!resultDt.getCategoryPath().equals(myCategoryPath)) {
						// DT Is there a command that already handles category path change resulting in conflict name?
						resultDt.setCategoryPath(myCategoryPath);
					}
					myResolvedDts.put(myID, resultDt);
					latestResolvedDts.put(resultID, resultDt);
				}
				catch (DataTypeDependencyException e) {
					String msg = "Cannot replace data type named " + latestDt.getName() +
						".\nProblem: " + e.getMessage();
					MergeManager.showBlockingError("Error Replacing Data Type", msg);
				}
				catch (DuplicateNameException e) {
					// DT Need to rename using conflict name if setCategoryPath causes duplicate?
					e.printStackTrace();
				}
				break;
			case OPTION_ORIGINAL:
				// remove the Latest that was added.
				DataType latestDt3 = dtms[RESULT].getDataType(sourceArchive, dataTypeID);
				long resultId3 = dtms[RESULT].getID(latestDt3);
				if (dtms[RESULT].remove(latestDt3, currentMonitor)) {
					latestResolvedDts.put(resultId3, null);
				}
				break;
		}
	}

	private void changeSourceArchive(long dtID) {

		int optionToUse = (dataTypeChoice == ASK_USER) ? conflictOption : dataTypeChoice;
		switch (optionToUse) {
			case OPTION_LATEST:
				// Latest data type's source archive is what we already have
				break;
			case OPTION_MY:
				// Set to My data type's source archive
				updateDataTypeSource(dtID, dtms[MY], myResolvedDts);
				break;
			case OPTION_ORIGINAL:
				// Set to Original data type's source archive
				updateDataTypeSource(dtID, dtms[ORIGINAL], origResolvedDts);
				break;
		}
	}

	private void dataTypeChanged(long id) {

		int optionToUse = (dataTypeChoice == ASK_USER) ? conflictOption : dataTypeChoice;
		switch (optionToUse) {
			case OPTION_LATEST:
				DataType latestDt = dtms[RESULT].getDataType(id);
				if (latestDt == null) {
					dataTypeDeleted(id);
				}
				else {
					// use data type from latest, so no action required
					updateHashTables(id, latestDt, latestResolvedDts);
				}
				break;
			case OPTION_MY:
				// use my data type
				DataType myDt = dtms[MY].getDataType(id);
				if (myDt == null) {
					dataTypeDeleted(id);
				}
				else {
					updateDataType(id, dtms[MY], myResolvedDts, true);
				}
				break;
			case OPTION_ORIGINAL:
				// put the original back
				dtms[ORIGINAL].getDataType(id);
				updateDataType(id, dtms[ORIGINAL], origResolvedDts, true);
				break;
		}
	}

	/**
	 * Process data type moved or renamed.
	 * @param id data type ID
	 * @return true if the data type was added because it was deleted
	 * in RESULT; false if the data type did not have to be added
	 */
	private boolean dataTypeRenamedOrMoved(long id) {
		DataType newDt = null;

		switch (conflictOption) {
			case OPTION_LATEST:
				// use name from latest, so no action required
				break;
			case OPTION_MY:
				// use name from my program
				DataType myDt = dtms[MY].getDataType(id);
				newDt = updateDataTypeName(id, myDt, myResolvedDts);
				break;

			case OPTION_ORIGINAL:
				DataType origDt = dtms[ORIGINAL].getDataType(id);
				newDt = updateDataTypeName(id, origDt, origResolvedDts);
				break;
		}
		return newDt != null;
	}

	/**
	 * Update the data type name/category path in RESULT if it exists.
	 * If it does not exist, add it to RESULT.
	 * @param id id of data type
	 * @param dt data type to use as the source name and category path
	 * @param resolvedDataTypes hashtable that has resolved data types
	 * @return the new data type if one had to be added to RESULT; null if
	 * the data type existed
	 */
	private DataType updateDataTypeName(long id, DataType dt,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
		DataType resultDt = dtms[RESULT].getDataType(id);
		DataType newDt = null;
		if (resultDt != null) {
			setDataTypeName(resultDt, dt);
			setCategoryPath(resultDt, dt.getCategoryPath());
		}
		else {
			// create the result data type which was deleted
			newDt = addDataType(id, dt, resolvedDataTypes);
		}
		return newDt;
	}

	private void dataTypeDeleted(long id) {
		DataType latestDt = dtms[RESULT].getDataType(id);
		DataType myDt = dtms[MY].getDataType(id);

		switch (conflictOption) {
			case OPTION_LATEST:
				if (latestDt == null) {
					if (!myDtAddedList.contains(Long.valueOf(id))) {
						// remove the data type if it was already added
						DataType dt = myResolvedDts.get(id);
						if (dt != null) {
							dtms[RESULT].remove(dt, currentMonitor);
							origResolvedDts.remove(id);
							myResolvedDts.remove(id);
						}
					}
				}
				break;

			case OPTION_MY:
				if (myDt == null) {
					if (latestDt != null) {
						dtms[RESULT].remove(latestDt, currentMonitor);
					}
				}
				else {
					// choose my data type
					addDataType(id, myDt, myResolvedDts);
				}
				break;
			case OPTION_ORIGINAL:
				// put data type back
				DataType origDt = dtms[ORIGINAL].getDataType(id);
				addDataType(id, origDt, origResolvedDts);
				break;
		}
	}

	/**
	 * Set category path.  If name conflict occurs within new category
	 * the specified dt will remain within its current category
	 * @param dt datatype whose category is to changed
	 * @param newPath new category path
	 */
	private void setCategoryPath(DataType dt, CategoryPath newPath) {
		if (dt.getCategoryPath().equals(newPath)) {
			return;
		}
		try {
			dt.setCategoryPath(newPath);
		}
		catch (DuplicateNameException e) {
			// ignore - no change made
		}
	}

	private DataType updateDataType(long id, DataTypeManager dtm,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes, boolean updatePath) {
		DataType resultDt = dtms[RESULT].getDataType(id);
		DataType myDt = dtm.getDataType(id);

		if (resultDt == null) {
			// get the equivalent result data type from hash table of resolved data types.
			resultDt = resolvedDataTypes.get(id);
		}
		if (resultDt == null) {
			// hasn't been resolved and was deleted in RESULT
			resultDt = addDataType(id, myDt, resolvedDataTypes);
		}
		else {

			if (resultDt instanceof Composite) {
				updateComposite(id, (Composite) myDt, (Composite) resultDt, resolvedDataTypes);
			}
			else if (resultDt instanceof FunctionDefinition) {
				updateFunctionDef(id, (FunctionDefinition) myDt, (FunctionDefinition) resultDt,
					resolvedDataTypes);
			}
			else if (resultDt instanceof Enum) {
				((Enum) resultDt).replaceWith(myDt);
			}
			else {
				try {
					resultDt = dtms[RESULT].replaceDataType(resultDt, myDt, true);
				}
				catch (DataTypeDependencyException e) {
					String msg = "Cannot replace data type named " + resultDt.getName() +
						".\nProblem: " + e.getMessage();
					MergeManager.showBlockingError("Error Replacing Data Type", msg);
					return null;
				}
			}
		}
		updateHashTables(id, resultDt, resolvedDataTypes);
		if (updatePath && !resultDt.getCategoryPath().equals(myDt.getCategoryPath())) {
			setCategoryPath(resultDt, myDt.getCategoryPath());
		}

		return resultDt;
	}

	private DataType updateDataTypeSource(long id, DataTypeManager dtm,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
		DataType resultDt = dtms[RESULT].getDataType(id);
		DataType myDt = dtm.getDataType(id);
		SourceArchive mySourceArchive = myDt.getSourceArchive();

		if (resultDt == null) {
			// get the equivalent result data type from hash table of resolved data types.
			resultDt = resolvedDataTypes.get(id);
		}
		if (resultDt == null) {
			// hasn't been resolved and was deleted in RESULT
			resultDt = addDataType(id, myDt, resolvedDataTypes);
		}
		else {

			SourceArchive resultSourceArchive = resultDt.getSourceArchive();
			if (!resultSourceArchive.getSourceArchiveID()
					.equals(mySourceArchive.getSourceArchiveID())) {
				resultDt.setSourceArchive(mySourceArchive);
			}
		}
		updateHashTables(id, resultDt, resolvedDataTypes);
		return resultDt;
	}

	/**
	 * 
	 * @param dataTypeID the ID (key) of the data type to be added.
	 * @param dataType the data type to be added.
	 * @param resolvedDataTypes table which maps the dataTypeID to the resulting data type within
	 * this data type manager.
	 * @return the resulting data type in this data type manager.
	 */
	private DataType addDataType(long dataTypeID, DataType dataType,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {

		DataType existingDt = resolvedDataTypes.get(dataTypeID);
		if (existingDt != null) {
			return existingDt; // Data type is already resolved and mapped in the table.
		}

		if (!myDtAddedList.contains(Long.valueOf(dataTypeID))) {
			existingDt = dtms[RESULT].getDataType(dataTypeID);
			if (existingDt != null) {
				Msg.warn(this, "Unexpectedly found data type \"" + existingDt.getPathName() +
					"\" when trying to add it.");
				return existingDt;
			}
		}

		DataType newDt = dataType;
		if (dataType instanceof Composite) {
			return addComposite(dataTypeID, (Composite) dataType, resolvedDataTypes);
		}
		if (dataType instanceof Pointer) {
			newDt = createPointer(dataTypeID, (Pointer) dataType, resolvedDataTypes);
		}
		else if (dataType instanceof Array) {
			newDt = createArray(dataTypeID, (Array) dataType, resolvedDataTypes);
		}
		else if (dataType instanceof TypeDef) {
			newDt = createTypeDef(dataTypeID, (TypeDef) dataType, resolvedDataTypes);
		}
		else if (dataType instanceof FunctionDefinition) {
			newDt = addFunctionDef(dataTypeID, (FunctionDefinition) dataType, resolvedDataTypes);
		}
		// If we have a new data type, resolve it using the default handler.
		if (newDt != null) {
			newDt = dtms[RESULT].addDataType(newDt, DataTypeConflictHandler.DEFAULT_HANDLER);
			updateHashTables(dataTypeID, newDt, resolvedDataTypes);
		}
		return newDt;
	}

	/**
	 * Get the resolved data type from the given table;
	 * If the data type has not been resolved yet, then use the one from
	 * the results if the id was not added in MY program.
	 * @param id id of data type
	 * @param dt the data type
	 * @return resolved data type that corresponds to id
	 */
	private DataType getResolvedBaseType(long id, DataType dt,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
		DataTypeManager dtm = dt.getDataTypeManager();

		boolean doCheck = false;
		DataType baseDt = dt;
		if (baseDt instanceof TypeDef td) {
			baseDt = td.getDataType();
			doCheck = true;
		}
		if ((baseDt instanceof Pointer) || (baseDt instanceof Array)) {
			baseDt = DataTypeUtilities.getBaseDataType(baseDt);
			doCheck = true;
		}

		if (baseDt == null || baseDt == DataType.DEFAULT) {
			return DataType.DEFAULT; // force DEFAULT - null will be misconstrued
		}

		if (!doCheck) {
			throw new AssertException(
				"Unexpected condition - method only valid for typedef, pointer or array");
		}

		long baseID = dtm.getID(baseDt);
		DataType resolvedDt = resolvedDataTypes.get(baseID);
		if (resolvedDt == null) {
			// Haven't resolved this yet.
			// use dt from results
			if (!myDtAddedList.contains(Long.valueOf(baseID))) {
				resolvedDt = dtms[RESULT].getDataType(baseID);
				if (resolvedDt == null) {
					if (baseDt instanceof BuiltIn ||
						origDtConflictList.contains(Long.valueOf(baseID))) {
						// was deleted, but add it back so we can create
						// data types depending on it; will get resolved later
						resolvedDt = addDataType(baseID, baseDt, resolvedDataTypes);
					}
					else {
						// Removed in latest so fix up later.
						fixUpList.add(new FixUpInfo(id, baseID, baseDt, -1, resolvedDataTypes));
					}
				}
				else {
					resolvedDataTypes.put(baseID, resolvedDt);
				}
			}
			else {
				// Added in My, but hasn't processed yet, so fixup later.
				fixUpList.add(new FixUpInfo(id, baseID, baseDt, -1, resolvedDataTypes));
			}
		}
		return resolvedDt;
	}

	private DataType createPointer(long id, Pointer pointerDt,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
		DataType innerDt = pointerDt.getDataType();
		if (innerDt == DataType.DEFAULT || innerDt == null) {
			return pointerDt;
		}
		DataType resolvedDt = getResolvedBaseType(id, pointerDt, resolvedDataTypes);
		if (resolvedDt != null) {
			if ((innerDt instanceof Pointer) || (innerDt instanceof Array) ||
				(innerDt instanceof TypeDef)) {
				resolvedDt = addDataType(innerDt.getDataTypeManager().getID(innerDt), innerDt,
					resolvedDataTypes);
			}
			if (resolvedDt != null) {
				return PointerDataType.getPointer(resolvedDt,
					pointerDt.hasLanguageDependantLength() ? -1 : pointerDt.getLength());
			}
		}
		return null;
	}

	private DataType createTypeDef(long id, TypeDef originalTypeDef,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
		DataType innerDataType = originalTypeDef.getDataType();
		if (innerDataType == DataType.DEFAULT) {
			return originalTypeDef;
		}

		SourceArchive originalSourceArchive = originalTypeDef.getSourceArchive();
		SourceArchive resultSourceArchive =
			getDataTypeManager(resolvedDataTypes).resolveSourceArchive(originalSourceArchive);
		DataType resolvedBaseDt = getResolvedBaseType(id, originalTypeDef, resolvedDataTypes);
		if (resolvedBaseDt != null) {
			if ((innerDataType instanceof Array) || (innerDataType instanceof Pointer) ||
				(innerDataType instanceof TypeDef)) {
				resolvedBaseDt =
					addDataType(innerDataType.getDataTypeManager().getID(innerDataType),
						innerDataType, resolvedDataTypes);
			}

			if (resolvedBaseDt != null) {
				TypedefDataType typedefDataType =
					new TypedefDataType(originalTypeDef.getCategoryPath(),
						originalTypeDef.getName(), resolvedBaseDt, originalTypeDef.getUniversalID(),
						resultSourceArchive, originalTypeDef.getLastChangeTime(),
						originalTypeDef.getLastChangeTimeInSourceArchive(), dtms[RESULT]);
				return typedefDataType;
			}
		}
		return null;
	}

	private DataType createArray(long id, Array array,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
		DataType dt = array.getDataType();
		if (dt == DataType.DEFAULT) {
			return array;
		}

		DataType resolvedDt = getResolvedBaseType(id, array, resolvedDataTypes);
		if (resolvedDt != null) {
			if ((dt instanceof Array) || (dt instanceof Pointer) || (dt instanceof TypeDef)) {
				resolvedDt = addDataType(dt.getDataTypeManager().getID(dt), dt, resolvedDataTypes);
			}
			if (resolvedDt != null) {
				int elementLen = (resolvedDt instanceof Dynamic) ? array.getElementLength()
						: resolvedDt.getLength();
				return new ArrayDataType(resolvedDt, array.getNumElements(), elementLen);
			}
		}
		return null;
	}

	private DataType addComposite(long id, Composite myDt,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {

		long oldLastChangeTime = myDt.getLastChangeTime();
		long oldLastChangeTimeInSourceArchive = myDt.getLastChangeTimeInSourceArchive();
		DataType newDt = myDt.clone(dtms[RESULT]);
		updateComposite(id, myDt, (Composite) newDt, resolvedDataTypes);

		SourceArchive originalSourceArchive = myDt.getSourceArchive();
		SourceArchive resultSourceArchive =
			getDataTypeManager(resolvedDataTypes).resolveSourceArchive(originalSourceArchive);
		newDt.setSourceArchive(resultSourceArchive);
		newDt = dtms[RESULT].addDataType(newDt, DataTypeConflictHandler.DEFAULT_HANDLER);
		newDt.setLastChangeTime(oldLastChangeTime);
		newDt.setLastChangeTimeInSourceArchive(oldLastChangeTimeInSourceArchive);
		updateHashTables(id, newDt, resolvedDataTypes);
		return newDt;

	}

	private DataType addFunctionDef(long id, FunctionDefinition myDt,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
		FunctionDefinition newDt = (FunctionDefinition) myDt.clone(dtms[RESULT]);
		setCategoryPath(newDt, myDt.getCategoryPath());
		updateFunctionDef(id, myDt, newDt, resolvedDataTypes);
		return newDt;
	}

	private void updateHashTables(long id, DataType newDt, Map<Long, DataType> resolvedDataTypes) {
		resolvedDataTypes.put(id, newDt);
		if (!myDtAddedList.contains(Long.valueOf(id))) {
			if (resolvedDataTypes == myResolvedDts) {
				origResolvedDts.put(id, newDt);
				latestResolvedDts.put(id, newDt);
			}
			else if (resolvedDataTypes == origResolvedDts) {
				myResolvedDts.put(id, newDt);
				latestResolvedDts.put(id, newDt);
			}
			else {
				origResolvedDts.put(id, newDt);
				myResolvedDts.put(id, newDt);
			}
		}
	}

	/**
	 * Get a previously resolved datatype.
	 * @param compID datatype ID
	 * @param resolvedDataTypes resolved datatype map
	 * @return resolved datatype or null if noth resolved or a critical dependency has been deleted
	 */
	private DataType getResolvedComponent(long compID, Map<Long, DataType> resolvedDataTypes) {
		DataType resolvedDt = resolvedDataTypes.get(compID);
		if (resolvedDt != null) {

			if (resolvedDt.isDeleted()) {
				return null;
			}

			boolean doCheck = false;
			DataType baseDt = resolvedDt;
			if (baseDt instanceof TypeDef td) {
				baseDt = td.getDataType();
				doCheck = true;
			}
			if ((baseDt instanceof Pointer) || (baseDt instanceof Array)) {
				baseDt = DataTypeUtilities.getBaseDataType(baseDt);
				doCheck = true;
			}

			if (doCheck) {
				if (baseDt != null && baseDt != DataType.DEFAULT) {
					DataTypeManager dtm = baseDt.getDataTypeManager();
					long baseID = dtm.getID(baseDt);
					if (!myDtAddedList.contains(Long.valueOf(baseID))) {
						DataType baseResultDt = dtms[RESULT].getDataType(baseID);
						if (baseResultDt == null || baseResultDt.isDeleted()) {
							return null; // base data type was deleted
						}
					}
				}
			}
			// else resolvedDataTypes was already updated if the component was deleted
		}
		return resolvedDt;
	}

	private void removeFixUps(long sourceDtID) {
		if (!fixUpIDSet.remove(sourceDtID)) {
			return;
		}
		Iterator<FixUpInfo> iter = fixUpList.iterator();
		while (iter.hasNext()) {
			FixUpInfo info = iter.next();
			if (info.id == sourceDtID) {
				iter.remove();
			}
		}
	}

	/**
	 * Compute the next non-packed component ordinal based upon the newly minted result
	 * component {@code resultDtc} and the offset of the next source component based upon
	 * the specified source component list {@code compList} and the current component
	 * index.
	 * @param resultDtc newly minted result component
	 * @param compList source component list
	 * @param index index of current source component
	 * @return next result component ordinal
	 */
	private static int computeNextNonPackedOrdinal(DataTypeComponent resultDtc,
			List<DataTypeComponent> compList, int index) {
		int nextOrdinal = resultDtc.getOrdinal() + 1;
		if (index < (compList.size() - 1)) {
			DataTypeComponent nextDtc = compList.get(index + 1);
			int undefinedSpace =
				nextDtc.getOffset() - resultDtc.getOffset() - resultDtc.getLength();
			if (undefinedSpace > 0) {
				nextOrdinal += undefinedSpace;
			}
		}
		return nextOrdinal;
	}

	private void updateStructure(long sourceDtID, Structure sourceDt, Structure destStruct,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {

		// NOTE: it is possible for the same destStruct to be updated more than once;
		// therefor we must cleanup any previous obsolete fixups
		removeFixUps(sourceDtID);

// TODO: Preserve timestamp?

		// Get an empty destination structure that is the correct size.
		destStruct.deleteAll();

		// Set to correct alignment and packing.
		updateAlignment(sourceDt, destStruct);

		DataTypeManager sourceDTM = sourceDt.getDataTypeManager();
		boolean packed = sourceDt.isPackingEnabled();

		// Add each of the defined components back in.
		DataTypeComponent[] comps = sourceDt.getDefinedComponents();

		// Component sequence must be flipped for components that share the same offset
		// (i.e., when zero-length components exist) to ensure that the insert at offset
		// does not alter the intended order.
		List<DataTypeComponent> compList = new ArrayList<>();
		int prevOffset = -1;
		int index = -1;
		for (DataTypeComponent dtc : comps) {
			int offset = dtc.getOffset();
			if (offset == prevOffset) {
				compList.add(index, dtc);
			}
			else {
				prevOffset = offset;
				index = compList.size();
				compList.add(dtc);
			}
		}
		comps = null; // prevent improper use

		// Track dependency errors to avoid duplicate popups
		HashMap<Long, String> badIdDtMsgs = new HashMap<>();

		for (int i = 0; i < compList.size(); i++) {

			DataTypeComponent sourceComp = compList.get(i);

			DataType sourceCompDt = sourceComp.getDataType();
			BitFieldDataType bfDt = null;
			String comment = sourceComp.getComment();
			DataType resultCompDt = null;

			if (sourceComp.isBitFieldComponent()) {
				// NOTE: primitive type will be used if unable to resolve base type
				bfDt = (BitFieldDataType) sourceCompDt;
				sourceCompDt = bfDt.getBaseDataType();
				if (sourceCompDt instanceof AbstractIntegerDataType) {
					resultCompDt = sourceCompDt.clone(dtms[RESULT]);
				}
			}

			long sourceComponentID = sourceDTM.getID(sourceCompDt);

			// Try to get a mapping of the source data type to a result data type.
			if (resultCompDt == null) {
				resultCompDt = getResolvedComponent(sourceComponentID, resolvedDataTypes);
			}

			if (resultCompDt == null) {
				// We didn't have a map entry for the data type.
				if (!myDtAddedList.contains(Long.valueOf(sourceComponentID))) {
					// Not added so should be in result if it wasn't deleted there.
					resultCompDt = dtms[RESULT].getDataType(sourceComponentID);
				}
				if (resultCompDt == null) {
					// Not added/resolved yet
					// put an entry in the fixup list
					fixUpList.add(new FixUpInfo(sourceDtID, sourceComponentID,
						sourceComp.getOrdinal(), sourceComp, resolvedDataTypes));
					fixUpIDSet.add(sourceDtID);
				}
				if (bfDt != null &&
					(resultCompDt == null || !BitFieldDataType.isValidBaseDataType(resultCompDt))) {
					// use primitive type as fixup placeholder
					resultCompDt = bfDt.getPrimitiveBaseDataType();
				}
			}

			if (resultCompDt != null && !resultCompDt.isDeleted()) {

				long dtId = dtms[RESULT].getID(resultCompDt);
				String badMsg = badIdDtMsgs.get(Long.valueOf(dtId));

				int length = resultCompDt.getLength();
				if (length <= 0) {
					length = sourceComp.getLength();
				}

				// There is a matching component data type in the result.
				if (packed) {
					if (bfDt != null) {
						try {
							destStruct.addBitField(resultCompDt, bfDt.getDeclaredBitSize(),
								sourceComp.getFieldName(), comment);
						}
						catch (InvalidDataTypeException e) {
							displayError(destStruct, e);
							// Try again with primitive base type
							DataType primitiveBaseDt = bfDt.getPrimitiveBaseDataType();
							comment = buildDataTypeFailureComment(sourceCompDt, e.getMessage(),
								sourceComp.getComment());
							try {
								destStruct.addBitField(primitiveBaseDt, bfDt.getDeclaredBitSize(),
									sourceComp.getFieldName(), comment);
							}
							catch (InvalidDataTypeException exc) {
								throw new RuntimeException(exc); // unexpected
							}
						}
					}
					else if (badMsg == null) {
						try {
							// If I have compDt, it should now be from result DTM.
							destStruct.add(resultCompDt, length, sourceComp.getFieldName(),
								comment);
						}
						catch (IllegalArgumentException e) {
							comment =
								buildDataTypeFailureComment(sourceCompDt, e.getMessage(), comment);
							destStruct.add(BadDataType.dataType, sourceComp.getLength(),
								sourceComp.getFieldName(), comment);
							if (e.getCause() instanceof DataTypeDependencyException) {
								badIdDtMsgs.put(dtId, e.getMessage());
							}
							displayError(destStruct, e);
						}
					}
					else {
						// Preserve non-fixup ordinal with bad placeholder
						comment = buildDataTypeFailureComment(sourceCompDt, badMsg, comment);
						destStruct.add(BadDataType.dataType, sourceComp.getLength(),
							sourceComp.getFieldName(), badMsg + "; " + comment);
					}
				}
				else if (bfDt != null) {
					// non-packed bitfield
					try {
						destStruct.insertBitFieldAt(sourceComp.getOffset(), sourceComp.getLength(),
							bfDt.getBitOffset(), resultCompDt, bfDt.getDeclaredBitSize(),
							sourceComp.getFieldName(), comment);
					}
					catch (InvalidDataTypeException e) {
						displayError(destStruct, e);
						// Try again with primitive base type
						DataType primitiveBaseDt = bfDt.getPrimitiveBaseDataType();
						comment = buildDataTypeFailureComment(sourceCompDt, e.getMessage(),
							sourceComp.getComment());
						try {
							destStruct.addBitField(primitiveBaseDt, bfDt.getDeclaredBitSize(),
								sourceComp.getFieldName(), comment);
						}
						catch (InvalidDataTypeException exc) {
							throw new RuntimeException(exc); // unexpected
						}
					}
				}
				else {
					// normal non-packed component
					if (badMsg == null) {
						try {
							// If not last component must constrain length to original component size
							if (i < compList.size() - 1) {
								int offset = sourceComp.getOffset();
								DataTypeComponent nextDtc = compList.get(i + 1);
								int available = nextDtc.getOffset() - offset;
								if (length > available) {
									// The data type is too big, so adjust the component length to what will fit.
									int extraBytesNeeded = length - available;
									length = available;
									// Output a warning indicating the structure has a data type that doesn't fit.
									String message =
										"Structure Merge: Not enough undefined bytes to fit " +
											resultCompDt.getPathName() + " in structure " +
											destStruct.getPathName() + " at offset 0x" +
											Integer.toHexString(offset) + "." + "\nIt needs " +
											extraBytesNeeded + " more byte(s) to be able to fit.";
									Msg.warn(this, message);
								}
							}

							destStruct.insertAtOffset(sourceComp.getOffset(), resultCompDt, length,
								sourceComp.getFieldName(), comment);
						}
						catch (IllegalArgumentException e) {
							comment =
								buildDataTypeFailureComment(sourceCompDt, e.getMessage(), comment);
							destStruct.insertAtOffset(sourceComp.getOffset(), BadDataType.dataType,
								length, sourceComp.getFieldName(), comment);

							if (e.getCause() instanceof DataTypeDependencyException) {
								badIdDtMsgs.put(dtId, e.getMessage());
							}
							displayError(destStruct, e);
						}
					}
					else {
						// Preserve non-fixup ordinal with bad placeholder
						comment = buildDataTypeFailureComment(sourceCompDt, badMsg, comment);
						destStruct.insertAtOffset(sourceComp.getOffset(), BadDataType.dataType,
							sourceComp.getLength(), sourceComp.getFieldName(), comment);
					}
				}
			}
			else if (packed) {
				// Add fixup placeholder to prevent the ordinal values and component sizes from 
				// changing.  Nothing we can do about packing which may be affected.
				// These should get fixed-up later.
				destStruct.add(BadDataType.dataType, sourceComp.getLength(),
					sourceComp.getFieldName(), comment);
			}
			else {
				// Add fixup placeholder to prevent the ordinal values and component sizes from 
				// changing.  These should get fixed-up later.
				destStruct.insertAtOffset(sourceComp.getOffset(), BadDataType.dataType,
					sourceComp.getLength(), sourceComp.getFieldName(), comment);
			}
		}
		if (!packed) {
			adjustStructureSize(destStruct, sourceDt.getLength());
		}
	}

	/**
	 * Bitfield insertions can cause excess growth of structure which must be trimmed.
	 * @param struct structure to be trimmed
	 * @param preferredSize preferred structure size
	 */
	private static void adjustStructureSize(Structure struct, int preferredSize) {

		DataTypeComponent dtc = struct.getComponentContaining(preferredSize);
		if (dtc == null) {
			struct.growStructure(preferredSize - struct.getLength());
			return;
		}

		int startOrdinal = dtc.getOrdinal();
		if (dtc.getOffset() != preferredSize) {
			++startOrdinal;
		}

		for (int i = struct.getNumComponents() - 1; i >= startOrdinal; i--) {
			DataTypeComponent comp = struct.getComponent(i);
			if (comp.getOffset() < preferredSize || comp.getDataType() != DataType.DEFAULT) {
				break;
			}
			struct.delete(i);
		}
	}

	private void displayError(Composite destComposite, Exception e) {
		String msg = "Some of your changes to " + destComposite.getName() +
			" cannot be merged.\nProblem: " + e.getMessage();
		String typeName = (destComposite instanceof Union) ? "Union" : "Structure";
		MergeManager.showBlockingError(typeName + " Update Failed", msg);
	}

	private void updateUnion(long sourceDtID, Union sourceDt, Union destUnion,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {

		// NOTE: it is possible for the same destUnion to be updated more than once;
		// therefor we must cleanup any previous obsolete fixups
		removeFixUps(sourceDtID);

// TODO: Preserve timestamp?

		// Remove all the components from the destination union.
		while (destUnion.getNumComponents() > 0) {
			destUnion.delete(0);
		}

		// Set to correct alignment and packing.
		updateAlignment(sourceDt, destUnion);

		DataTypeManager sourceDTM = sourceDt.getDataTypeManager();

		// Add each of the defined components back in.
		for (DataTypeComponent sourceComp : sourceDt.getComponents()) {
			DataType sourceCompDt = sourceComp.getDataType();
			BitFieldDataType bfDt = null;
			String comment = sourceComp.getComment();
			DataType resultCompDt = null;

			if (sourceComp.isBitFieldComponent()) {
				// NOTE: primitive type will be used if unable to resolve base type
				bfDt = (BitFieldDataType) sourceCompDt;
				sourceCompDt = bfDt.getBaseDataType();
				if (sourceCompDt instanceof AbstractIntegerDataType) {
					resultCompDt = sourceCompDt.clone(dtms[RESULT]);
				}
			}

			long sourceCompID = sourceDTM.getID(sourceCompDt);

			// Try to get a mapping of the source data type to a result data type.
			if (resultCompDt == null) {
				resultCompDt = getResolvedComponent(sourceCompID, resolvedDataTypes);
			}

			if (resultCompDt == null) {
				if (!myDtAddedList.contains(Long.valueOf(sourceCompID))) {

					// Not added so should be in result if it wasn't deleted there.
					DataType resultsDt = dtms[RESULT].getDataType(sourceCompID);
					if (resultsDt != null) {
						resultCompDt = resultsDt;
					}
					else {
						// must  have been deleted in LATEST
						// put an entry in RESULT for later fixup if
						// it is in conflict
						FixUpInfo info = new FixUpInfo(sourceDtID, sourceCompID,
							sourceComp.getOrdinal(), sourceComp, resolvedDataTypes);
						fixUpList.add(info);
						fixUpIDSet.add(sourceDtID);
					}
				}
				else {
					// Not added/resolved yet
					// put an entry in RESULT for later fixup
					fixUpList.add(new FixUpInfo(sourceDtID, sourceCompID, sourceComp.getOrdinal(),
						sourceComp, resolvedDataTypes));
					fixUpIDSet.add(sourceDtID);
				}
				if (bfDt != null &&
					(resultCompDt == null || !BitFieldDataType.isValidBaseDataType(resultCompDt))) {
					// use primitive type as fallback (may get fixed-up later)
					resultCompDt = bfDt.getPrimitiveBaseDataType();
				}
			}
			if (resultCompDt != null) {
				if (bfDt != null) {
					// bitfield component in union
					try {
						destUnion.addBitField(resultCompDt, bfDt.getDeclaredBitSize(),
							sourceComp.getFieldName(), comment);
					}
					catch (InvalidDataTypeException e) {
						displayError(destUnion, e);
						// Try again with primitive base type
						DataType primitiveBaseDt = bfDt.getPrimitiveBaseDataType();
						comment = buildDataTypeFailureComment(sourceCompDt, e.getMessage(),
							sourceComp.getComment());
						try {
							destUnion.addBitField(primitiveBaseDt, bfDt.getDeclaredBitSize(),
								sourceComp.getFieldName(), comment);
						}
						catch (InvalidDataTypeException exc) {
							throw new RuntimeException(exc); // unexpected
						}
					}
				}
				else {
					// Normal component in union
					int compLen = resultCompDt.getLength();
					if (compLen <= 0) {
						compLen = sourceComp.getLength();
					}
					try {
						destUnion.add(resultCompDt, compLen, sourceComp.getFieldName(), comment);
					}
					catch (IllegalArgumentException e) {
						comment =
							buildDataTypeFailureComment(sourceCompDt, e.getMessage(), comment);
						destUnion.add(BadDataType.dataType, compLen, sourceComp.getFieldName(),
							comment);
						displayError(destUnion, e);
					}
				}
			}
			else {
				// Add fixup placeholder to prevent the ordinal values and component sizes from 
				// changing.  Nothing we can do about packing which may be affected.
				// These should get fixed-up later.
				destUnion.add(BadDataType.dataType, sourceComp.getLength(),
					sourceComp.getFieldName(), comment);
			}
		}
	}

	private void updateAlignment(Composite sourceDt, Composite destinationDt) {
		if (sourceDt.isDefaultAligned()) {
			destinationDt.setToDefaultAligned();
		}
		else if (sourceDt.isMachineAligned()) {
			destinationDt.setToMachineAligned();
		}
		else {
			destinationDt.setExplicitMinimumAlignment(sourceDt.getExplicitMinimumAlignment());
		}
		if (sourceDt.isPackingEnabled()) {
			if (sourceDt.hasExplicitPackingValue()) {
				destinationDt.setExplicitPackingValue(sourceDt.getExplicitPackingValue());
			}
			else {
				destinationDt.setToDefaultPacking();
			}
		}
		else {
			destinationDt.setPackingEnabled(false);
		}
	}

	private void updateComposite(long sourceDtID, Composite sourceDt, Composite destDt,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {

		if (sourceDt instanceof Structure) {
			updateStructure(sourceDtID, (Structure) sourceDt, (Structure) destDt,
				resolvedDataTypes);
		}
		else {
			updateUnion(sourceDtID, (Union) sourceDt, (Union) destDt, resolvedDataTypes);
		}

	}

	private void updateFunctionDef(long sourceFunctionDefDtID,
			FunctionDefinition sourceFunctionDefDt, FunctionDefinition destDt,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {

		// NOTE: it is possible for the same function def to be updated more than once;
		// therefor we must cleanup any previous obsolete fixups
		removeFixUps(sourceFunctionDefDtID);

		long oldLastChangeTime = sourceFunctionDefDt.getLastChangeTime();
		long oldLastChangeTimeInSourceArchive =
			sourceFunctionDefDt.getLastChangeTimeInSourceArchive();
		DataTypeManager sourceDTM = sourceFunctionDefDt.getDataTypeManager();
		DataType sourceReturnType = sourceFunctionDefDt.getReturnType();
		ParameterDefinition[] sourceVars = sourceFunctionDefDt.getArguments();
		ParameterDefinition[] destVars = new ParameterDefinition[sourceVars.length];
		boolean sourceHasVarArgs = sourceFunctionDefDt.hasVarArgs();
		boolean sourceHasNoReturn = sourceFunctionDefDt.hasNoReturn();

		DataType resolvedRDT = DataType.DEFAULT;
		if (sourceReturnType != null) {
			long returnTypeID = sourceDTM.getID(sourceReturnType);
			resolvedRDT = getResolvedParam(sourceFunctionDefDtID, returnTypeID, sourceReturnType,
				-1, resolvedDataTypes);
		}
		destDt.setReturnType(resolvedRDT);

		for (int i = 0; i < sourceVars.length; i++) {
			DataType varDt = sourceVars[i].getDataType();
			long varID = sourceDTM.getID(varDt);
			DataType resolvedDt =
				getResolvedParam(sourceFunctionDefDtID, varID, varDt, i, resolvedDataTypes);
			destVars[i] = new ParameterDefinitionImpl(sourceVars[i].getName(), resolvedDt,
				sourceVars[i].getComment());
		}
		destDt.setArguments(destVars);
		destDt.setVarArgs(sourceHasVarArgs);
		destDt.setNoReturn(sourceHasNoReturn);

		destDt.setLastChangeTime(oldLastChangeTime);
		destDt.setLastChangeTimeInSourceArchive(oldLastChangeTimeInSourceArchive);
	}

	/**
	 * Get the resolved data type for either the return type or a variable.
	 * @param id id of FunctionDefinition
	 * @param paramDatatypeID ID of either the return or variable dataty type ID
	 * @param sourceParamDataType source param datatype
	 * @param index &gt;=0 is the index of the variable; <0 means the paramID is
	 * the return type
	 * @param resolvedDataTypes hashtable to use for resolving
	 * @return resolved data type or the default data type if the data type
	 * has not been resolved yet
	 */
	private DataType getResolvedParam(long id, long paramDatatypeID, DataType sourceParamDataType,
			int index, MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
		DataType resolvedDt = getResolvedComponent(paramDatatypeID, resolvedDataTypes);
		if (resolvedDt == null) {
			if (!myDtAddedList.contains(Long.valueOf(paramDatatypeID))) {

				// Not added so should be in result if it wasn't deleted there.
				DataType resultsDt = dtms[RESULT].getDataType(paramDatatypeID);
				if (resultsDt != null) {
					resolvedDt = resultsDt;
				}
				else {
					// must  have been deleted in LATEST
					// put an entry in RESULT for later fixup if
					// it is in conflict
					resolvedDt = DataType.DEFAULT;
					FixUpInfo info = new FixUpInfo(id, paramDatatypeID, sourceParamDataType, index,
						resolvedDataTypes);
					fixUpList.add(info);
					fixUpIDSet.add(id);
				}
			}
			else {
				// Not added/resolved yet
				// put an entry in RESULT for later fixup
				resolvedDt = DataType.DEFAULT;
				fixUpList.add(new FixUpInfo(id, paramDatatypeID, sourceParamDataType, index,
					resolvedDataTypes));
				fixUpIDSet.add(id);
			}
		}
		return resolvedDt;
	}

	/**
	 * Process data types that were changed (renamed, moved, or edited) in
	 * MY program, but are not conflicts, i.e., not renamed, moved or edited
	 * in LATEST. The corresponding data type in RESULT program is updated.
	 * @throws CancelledException if task is cancelled
	 */
	private void processDataTypeChanges() throws CancelledException {

		for (Long element : myDtChangeList) {
			currentMonitor.checkCancelled();
			currentMonitor.setProgress(++progressIndex);

			long id = element.longValue();

			DataType dt = dtms[MY].getDataType(id);
			if ((dt instanceof Pointer) || (dt instanceof Array) || (dt instanceof BuiltIn)) {
				continue;
			}

			processDataTypeRenamed(id);
			processDataTypeMoved(id);
			processDataTypeEdited(id);
			processDataTypeSourceChanged(id);
		}
	}

	/**
	 * Process categories that were renamed in MY program, but are not
	 * conflicts, i.e., not renamed, moved, or deleted in LATEST.
	 * @param id category ID
	 */
	private void processCategoryRenamed(long id) {
		if (categoryWasRenamed(id, dtms[MY])) {
			Category resultCat = dtms[RESULT].getCategory(id);
			if (resultCat != null) {
				Category myCat = dtms[MY].getCategory(id);
				String myCatName = myCat.getName();
				if (!resultCat.getName().equals(myCatName)) {
					setCategoryName(resultCat, myCatName);
				}
			}
		}
	}

	/**
	 * Process categories that were moved in MY program, but are not
	 * conflicts, i.e., not renamed, moved, or deleted in LATEST.
	 * @param id category ID
	 */
	private void processCategoryMoved(long id) {
		Category myCat = dtms[MY].getCategory(id);
		if (myCat == null) {
			return;
		}
		if (categoryWasMoved(id, dtms[MY])) {
			// move the category in results program
			Category resultCat = dtms[RESULT].getCategory(id);
			if (resultCat != null) {
				Category myParent = myCat.getParent();
				Category resultNewParent = dtms[RESULT].getCategory(myParent.getCategoryPath());

				if (resultNewParent == null) {
					resultNewParent = dtms[RESULT].createCategory(myParent.getCategoryPath());
				}
				moveCategory(resultNewParent, resultCat);
			}
		}
	}

	/**
	 * Process categories that were deleted in MY program, but are not
	 * conflicts, i.e., not renamed, moved, or deleted in LATEST.
	 * @param id category ID
	 */
	private void processCategoryDeleted(long id) {
		Category myCat = dtms[MY].getCategory(id);
		if (myCat == null) {
			Category resultCat = dtms[RESULT].getCategory(id);
			if (resultCat != null) {
				// check added data types that have this category path as
				// the parent
				if (!isParent(resultCat.getCategoryPath())) {
					resultCat.getParent().removeCategory(resultCat.getName(), currentMonitor);
				}
			}
		}

	}

	private boolean isParent(CategoryPath catPath) {
		for (Long id : myDtAddedList) {
			DataType dt = dtms[MY].getDataType(id.longValue());
			if (catPath.equals(dt.getCategoryPath())) {
				return true;
			}
		}
		return false;
	}

	private void moveCategory(Category newParent, Category category) {
		Category[] cats = newParent.getCategories();
		// make sure category is not already in newParent
		for (Category cat : cats) {
			if (category == cat) {
				return;
			}
		}
		String newName = category.getName();
		String baseName = newName;
		int index = newName.indexOf(DataType.CONFLICT_SUFFIX);
		if (index > 0) {
			baseName = newName.substring(0, index);
		}
		int oneUpNumber = 0;
		while (true) {
			try {

				if (newParent.getCategory(newName) == null) {
					newParent.moveCategory(category, currentMonitor);
					return;
				}
				++oneUpNumber;
				newName = baseName + DataType.CONFLICT_SUFFIX + oneUpNumber;
			}
			catch (DuplicateNameException e) {
				throw new AssertException("Got DuplicateNameException");
			}
			catch (IllegalArgumentException e) {
				// cannot move category
				return;
			}
		}
	}

	private void setCategoryName(Category category, String newName) {
		if (category.getName().equals(newName)) {
			return;
		}
		String name = newName;
		String baseName = newName;
		int index = newName.indexOf(DataType.CONFLICT_SUFFIX);
		if (index > 0) {
			baseName = newName.substring(0, index);
		}
		int oneUpNumber = 0;
		while (true) {
			try {
				category.setName(name);
				return;
			}
			catch (DuplicateNameException e) {
				++oneUpNumber;
				name = baseName + DataType.CONFLICT_SUFFIX + oneUpNumber;
			}
			catch (InvalidNameException e) {
				throw new AssertException("Got InvalidNameException: " + e);
			}
		}
	}

	private void setDataTypeName(DataType dt, DataType dtToCopy) {
		if (isAutoNamedTypedef(dtToCopy)) {
			if (dt instanceof TypeDef) {
				((TypeDef) dt).enableAutoNaming();
				return;
			}
		}
		String newName = dtToCopy.getName();
		if (dt.getName().equals(newName)) {
			return;
		}
		String baseName = newName;
		int index = newName.indexOf(DataType.CONFLICT_SUFFIX);
		if (index > 0) {
			baseName = newName.substring(0, index);
		}
		int oneUpNumber = 0;
		while (true) {
			try {
				dt.setName(newName);
				return;
			}
			catch (DuplicateNameException e) {
				++oneUpNumber;
				newName = baseName + DataType.CONFLICT_SUFFIX + oneUpNumber;
			}
			catch (InvalidNameException e) {
				throw new AssertException("Got InvalidNameException: " + e);
			}
		}
	}

	private boolean categoryWasMoved(long id, DataTypeManager dtm1, DataTypeManager dtm2) {
		Category cat1 = dtm1.getCategory(id);
		Category cat2 = dtm2.getCategory(id);
		if (cat1 != null && cat2 != null) {
			Category parent1 = cat1.getParent();
			Category parent2 = cat2.getParent();
			if (parent1 != null && parent2 != null) {
				return !parent1.getCategoryPath().equals(parent2.getCategoryPath());
			}
			if (parent1 == null && parent2 == null) {
				return false;
			}
			return true;
		}

		return false;
	}

	private boolean categoryWasMoved(long id, DataTypeManager dtm) {
		return categoryWasMoved(id, dtms[ORIGINAL], dtm);
	}

	private boolean categoryWasRenamed(long id, DataTypeManager dtm1, DataTypeManager dtm2) {
		Category cat1 = dtm1.getCategory(id);
		Category cat2 = dtm2.getCategory(id);
		if (cat1 != null && cat2 != null) {
			return !cat1.getName().equals(cat2.getName());
		}
		return false;
	}

	private boolean categoryWasRenamed(long id, DataTypeManager dtm) {
		return categoryWasRenamed(id, dtms[ORIGINAL], dtm);
	}

	private boolean dataTypeWasMoved(long id, DataTypeManager dtm) {
		return dataTypeWasMoved(id, dtms[ORIGINAL], dtm);
	}

	private boolean dataTypeWasMoved(long id, DataTypeManager dtm1, DataTypeManager dtm2) {
		DataType dt1 = dtm1.getDataType(id);
		DataType dt2 = dtm2.getDataType(id);
		if (dt1 != null && dt2 != null) {
			CategoryPath p1 = dt1.getCategoryPath();
			CategoryPath p2 = dt2.getCategoryPath();
			return !p1.equals(p2);
		}

		return false;
	}

	private boolean dataTypeWasRenamed(long id, DataTypeManager dtm) {
		return dataTypeWasRenamed(id, dtms[ORIGINAL], dtm);
	}

	private boolean isAutoNamedTypedef(DataType dt) {
		if (dt instanceof TypeDef) {
			TypeDef td = (TypeDef) dt;
			return td.isAutoNamed();
		}
		return false;
	}

	private boolean dataTypeWasRenamed(long id, DataTypeManager dtm1, DataTypeManager dtm2) {
		DataType dt1 = dtm1.getDataType(id);
		DataType dt2 = dtm2.getDataType(id);
		if (dt1 != null && dt2 != null) {
			if (isAutoNamedTypedef(dt1)) {
				return isAutoNamedTypedef(dt2);
			}
			else if (isAutoNamedTypedef(dt2)) {
				return false;
			}
			String name1 = dt1.getName();
			String name2 = dt2.getName();
			return !name1.equals(name2);
		}
		return false;
	}

	private boolean dataTypeWasChanged(long id, DataTypeManager dtm) {
		return dataTypeWasChanged(id, dtms[ORIGINAL], dtm);
	}

	private boolean dataTypeWasChanged(long id, DataTypeManager dtm1, DataTypeManager dtm2) {

		DataType dt1 = dtm1.getDataType(id);
		DataType dt2 = dtm2.getDataType(id);
		if (dt1 != null && dt2 != null) {
			if (dt1.getClass() == dt2.getClass()) {
				if (dt1 instanceof Composite) {
					Composite c1 = (Composite) dt1;
					Composite c2 = (Composite) dt2;
					return compositeDataTypeWasChanged(c1, c2);
				}
				return !dt1.isEquivalent(dt2);
			}
		}
		return false;
	}

	private int getNumDefinedComponents(Composite c) {
		if (c instanceof Structure) {
			return ((Structure) c).getNumDefinedComponents();
		}
		return c.getNumComponents();
	}

	private boolean compositeDataTypeWasChanged(Composite c1, Composite c2) {
		DataTypeManager dtm1 = c1.getDataTypeManager();
		DataTypeManager dtm2 = c2.getDataTypeManager();

		PackingType packingType = c1.getPackingType();
		AlignmentType alignmentType = c1.getAlignmentType();

		if ((packingType != c2.getPackingType()) || (alignmentType != c2.getAlignmentType()) ||
			(packingType == PackingType.EXPLICIT &&
				c1.getExplicitPackingValue() != c2.getExplicitPackingValue()) ||
			(alignmentType == AlignmentType.EXPLICIT &&
				c1.getExplicitMinimumAlignment() != c2.getExplicitMinimumAlignment())) {
			return true;
		}

		int c1ComponentCnt = getNumDefinedComponents(c1);
		int c2ComponentCnt = getNumDefinedComponents(c2);
		if (c1ComponentCnt != c2ComponentCnt) {
			return true;
		}

		boolean checkOffsets = false;

		if (c1 instanceof Structure) {
			if (!((Structure) c1).isPackingEnabled()) {
				if (c1.getNumComponents() != c2.getNumComponents()) {
					return true;
				}
				checkOffsets = true;
			}
		}

		DataTypeComponent[] c1Components = c1.getDefinedComponents();
		DataTypeComponent[] c2Components = c2.getDefinedComponents();
		for (int i = 0; i < c1ComponentCnt; i++) {
			DataTypeComponent dtc1 = c1Components[i];
			DataTypeComponent dtc2 = c2Components[i];
			if (isChangedComponent(dtc1, dtc2, dtm1, dtm2, checkOffsets)) {
				return true;
			}
		}
		return false;
	}

	private boolean isChangedComponent(DataTypeComponent dtc1, DataTypeComponent dtc2,
			DataTypeManager dtm1, DataTypeManager dtm2, boolean checkOffsets) {

		if (checkOffsets && dtc1.getOffset() != dtc2.getOffset()) {
			return true;
		}
		if (dtm1.getID(dtc1.getDataType()) != dtm2.getID(dtc2.getDataType())) {
			return true;
		}
		if (!Objects.equals(dtc1.getFieldName(), dtc2.getFieldName()) ||
			!Objects.equals(dtc1.getComment(), dtc2.getComment())) {
			return true;
		}
		return false;
	}

	private boolean dataTypeSourceWasChanged(long id, DataTypeManager dtm) {
		return dataTypeSourceWasChanged(id, dtms[ORIGINAL], dtm);
	}

	private boolean dataTypeSourceWasChanged(long id, DataTypeManager dtm1, DataTypeManager dtm2) {

		DataType dt1 = dtm1.getDataType(id);
		DataType dt2 = dtm2.getDataType(id);
		if (dt1 != null && dt2 != null) {
			SourceArchive sourceArchive1 = dt1.getSourceArchive();
			SourceArchive sourceArchive2 = dt2.getSourceArchive();
			if (!sourceArchive1.getSourceArchiveID().equals(sourceArchive2.getSourceArchiveID())) {
				return true;
			}
			UniversalID universalID1 = dt1.getUniversalID(); // UniversalID may be null.
			UniversalID universalID2 = dt2.getUniversalID(); // UniversalID may be null.
			if (universalID1 == null || universalID2 == null) {
				String msg = "Null Universal ID encountered for data type ID " + id +
					"\n    DataType1 is \"" + dt1.getPathName() + "\"." +
					"\n        Universal ID = " + universalID1 + "\n        DataType Class = " +
					dt1.getClass().getName() + "\n        DataTypeManager = " + dtm1.getName() +
					"\n        Source Archive = " + sourceArchive1.getName() +
					"\n    DataType2 is \"" + dt2.getPathName() + "\"." +
					"\n        Universal ID = " + universalID2 + "\n        DataType Class = " +
					dt2.getClass().getName() + "\n        DataTypeManager = " + dtm2.getName() +
					"\n        Source Archive = " + sourceArchive2.getName() + "        ";
				Msg.error(this, msg);
			}
			if (!Objects.equals(universalID1, universalID2)) {
				return true;
			}
		}
		return false;
	}

	private boolean dataTypeWasDeleted(long id, DataTypeManager dtm) {
		DataType dt1 = dtms[ORIGINAL].getDataType(id);
		DataType dt2 = dtm.getDataType(id);
		return dt1 != null && dt2 == null;
	}

	/**
	 * Handle conflicts with name changes; also determine whether the category
	 * was moved; if so, move the category according to the conflictOption
	 * selected. Moves are handled here because a rename and a move is
	 * considered to be a single conflict.
	 * @param id category ID
	 * @throws CancelledException if task is cancelled
	 */
	private void categoryRenamedOrMoved(long id) throws CancelledException {

		if (conflictOption == CANCELED) {
			throw new CancelledException();
		}
		int optionToUse = (categoryChoice == ASK_USER) ? conflictOption : categoryChoice;
		switch (optionToUse) {
			case OPTION_LATEST:
				// use name from latest, so no action required
				break;
			case OPTION_MY:
				// use name from my program
				useMyCategoryName(id);
				break;
			case OPTION_ORIGINAL:
				useOriginalCategoryName(id);
				break;
			case CANCELED:
				throw new CancelledException();
		}

	}

	private void useOriginalCategoryName(long id) {
		Category origCat = dtms[ORIGINAL].getCategory(id);
		Category resultCat = dtms[RESULT].getCategory(id);
		setCategoryName(resultCat, origCat.getName());
		if (!resultCat.getCategoryPath().equals(origCat.getCategoryPath())) {
			CategoryPath origParentCatPath = origCat.getCategoryPath().getParent();
			if (!dtms[RESULT].containsCategory(origParentCatPath)) {
				dtms[RESULT].createCategory(origParentCatPath);
			}
			Category parent = dtms[RESULT].getCategory(origCat.getCategoryPath().getParent());
			moveCategory(parent, resultCat);
		}
	}

	private void useMyCategoryName(long id) {
		Category myCat = dtms[MY].getCategory(id);
		Category resultCat = dtms[RESULT].getCategory(id);
		if (resultCat != null) {
			setCategoryName(resultCat, myCat.getName());
			if (!resultCat.getCategoryPath().equals(myCat.getCategoryPath())) {
				CategoryPath myParentCatPath = myCat.getCategoryPath().getParent();
				if (!dtms[RESULT].containsCategory(myParentCatPath)) {
					dtms[RESULT].createCategory(myParentCatPath);
				}
				Category resultParentCat =
					dtms[RESULT].getCategory(myCat.getCategoryPath().getParent());
				moveCategory(resultParentCat, resultCat);
			}
		}
		else {
			// create result category
			dtms[RESULT].createCategory(myCat.getCategoryPath());
		}
	}

	/**
	 * Handle conflicts on a category that was deleted in one program, and
	 * renamed or moved in another program.
	 * @param id category ID
	 * @throws CancelledException if operation is cancelled
	 */
	private void categoryDeleted(long id) throws CancelledException {

		Category myCat = dtms[MY].getCategory(id);
		Category latestCat = dtms[LATEST].getCategory(id);
		Category origCat = dtms[ORIGINAL].getCategory(id);

		if (conflictOption == CANCELED) {
			throw new CancelledException();
		}
		int optionToUse = (categoryChoice == ASK_USER) ? conflictOption : categoryChoice;
		switch (optionToUse) {
			case OPTION_LATEST:
				if (latestCat != null) {
					// make sure path still exists
					if (!dtms[RESULT].containsCategory(latestCat.getCategoryPath())) {
						dtms[RESULT].createCategory(latestCat.getCategoryPath());
					}
				}
				break;

			case OPTION_MY:
				if (myCat == null) {
					deleteLatestCategory(latestCat);
				}
				else {
					// choose my category
					dtms[RESULT].createCategory(myCat.getCategoryPath());
				}
				break;
			case OPTION_ORIGINAL:
				// put category back
				Category parentCat =
					dtms[RESULT].getCategory(origCat.getParent().getCategoryPath());
				if (latestCat != null) {
					if (categoryWasMoved(id, dtms[RESULT])) {
						Category resultCat = dtms[RESULT].getCategory(id);
						moveCategory(parentCat, resultCat);
					}
					else {
						Category resultCat = dtms[RESULT].getCategory(id);
						if (resultCat != null) {
							setCategoryName(resultCat, origCat.getName());
						}
						else {
							dtms[RESULT].createCategory(origCat.getCategoryPath());
						}
					}
				}
				else {
					dtms[RESULT].createCategory(origCat.getCategoryPath());
				}
				break;
			case CANCELED:
				throw new CancelledException();
		}
	}

	private void deleteLatestCategory(Category latestCat) {
		// delete the category from results program if the
		// paths on the data types in LATEST are different
		// from path on the data types in MY;
		DataType[] dts = latestCat.getDataTypes();
		boolean doDelete = true;
		if (dts.length > 0) {
			for (DataType dt : dts) {
				long dtID = dtms[LATEST].getID(dt);
				DataType myDt = dtms[MY].getDataType(dtID);
				if (myDt != null && myDt.getCategoryPath().equals(dt.getCategoryPath())) {
					doDelete = false;
					break;
				}
			}
		}
		else {
			Category[] cats = latestCat.getCategories();
			for (Category cat : cats) {
				long catID = cat.getID();
				Category c = dtms[MY].getCategory(catID);
				if (c != null &&
					c.getParent().getCategoryPath().equals(cat.getParent().getCategoryPath())) {
					doDelete = false;
					break;
				}
			}
		}

		if (doDelete) {
			Category parentCat = dtms[RESULT].getCategory(latestCat.getParent().getCategoryPath());
			if (parentCat != null) {
				parentCat.removeCategory(latestCat.getName(), TaskMonitor.DUMMY);
			}
		}
	}

	private void showArchiveMergePanel(final long id, final int conflictIndex) {
		UniversalID sourceID = new UniversalID(id);
		final SourceArchive mySourceArchive = dtms[MY].getSourceArchive(sourceID);
		final SourceArchive latestSourceArchive = dtms[LATEST].getSourceArchive(sourceID);
		final SourceArchive originalSourceArchive = dtms[ORIGINAL].getSourceArchive(sourceID);

		try {
			SwingUtilities.invokeAndWait(() -> {
				if (archiveMergePanel == null) {
					archiveMergePanel =
						new SourceArchiveMergePanel(mergeManager, totalConflictCount);
				}
				archiveMergePanel.setConflictInfo(conflictIndex, latestSourceArchive,
					mySourceArchive, originalSourceArchive);
			});
		}
		catch (InterruptedException e) {
			// ignore
		}
		catch (InvocationTargetException e) {
			e.printStackTrace();
		}
		mergeManager.setApplyEnabled(false);
		mergeManager.showComponent(archiveMergePanel, "SourceArchiveMerge",
			new HelpLocation(HelpTopics.REPOSITORY, "SourceArchiveConflict"));
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	private void showCategoryMergePanel(final long id, final int conflictIndex) {
		final Category myCat = dtms[MY].getCategory(id);
		final Category latestCat = dtms[LATEST].getCategory(id);
		Category originalCat = dtms[ORIGINAL].getCategory(id);
		final String latestPath = latestCat != null ? latestCat.getCategoryPathName() : null;
		final String path = myCat != null ? myCat.getCategoryPathName() : null;
		final String origPath = originalCat != null ? originalCat.getCategoryPathName() : null;

		try {
			SwingUtilities.invokeAndWait(() -> {
				if (catMergePanel == null) {
					catMergePanel = new CategoryMergePanel(mergeManager, totalConflictCount);
				}
				catMergePanel.setConflictInfo(conflictIndex, latestPath, path, origPath,
					categoryWasRenamed(id, dtms[LATEST]), categoryWasRenamed(id, dtms[MY]),
					categoryWasMoved(id, dtms[LATEST]), categoryWasMoved(id, dtms[MY]),
					latestCat == null, myCat == null);
			});
		}
		catch (InterruptedException e) {
			// ignore
		}
		catch (InvocationTargetException e) {
			e.printStackTrace();
		}
		mergeManager.setApplyEnabled(false);
		mergeManager.showComponent(catMergePanel, "CategoryMerge",
			new HelpLocation(HelpTopics.REPOSITORY, "DataTypeConflict"));
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	private void showDataTypeMergePanel(final int conflictIndex, final DataType latestDt,
			final DataType myDt, final DataType origDt) {
		try {
			SwingUtilities.invokeAndWait(() -> {
				if (dtMergePanel == null) {
					dtMergePanel = new DataTypeMergePanel(mergeManager, totalConflictCount);
				}
				dtMergePanel.setConflictInfo(conflictIndex, latestDt, myDt, origDt);
			});
		}
		catch (InterruptedException e) {
			// ignore
		}
		catch (InvocationTargetException e) {
			e.printStackTrace();
		}
		mergeManager.showComponent(dtMergePanel, "DataTypeMerge",
			new HelpLocation(HelpTopics.REPOSITORY, "DataTypeConflicts"));
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.

	}

	private void processDataTypesDeleted() throws CancelledException {
		for (Long element : myDtChangeList) {
			currentMonitor.checkCancelled();

			long id = element.longValue();
			processDataTypeDeleted(id);
		}
	}

	private void processDataTypesAdded() throws CancelledException {
		for (Long element : myDtAddedList) {
			currentMonitor.checkCancelled();
			currentMonitor.setProgress(++progressIndex);

			long myDtKey = element.longValue();
			DataType myDt = dtms[MY].getDataType(myDtKey);

			if (equivalentDataTypeFound(myDtKey, myDt)) {
				continue;
			}
			if ((myDt instanceof Composite) || (myDt instanceof Pointer) ||
				(myDt instanceof Array) || (myDt instanceof TypeDef) ||
				(myDt instanceof FunctionDefinition)) {
				// check components of composite or base type for pointers,
				// arrays, and typedefs
				addDataType(myDtKey, myDt, myResolvedDts);
			}
			else { // BuiltIn or Enum.
				DataType resolvedDt =
					dtms[RESULT].addDataType(myDt, DataTypeConflictHandler.DEFAULT_HANDLER);
				myResolvedDts.put(myDtKey, resolvedDt);
			}
		}
	}

	/**
	 * See if there is a data type in the result file that matches My data type based on
	 * name, path and contents.
	 * If there is a data type that is the same then return true.
	 * @param myDtID the database ID (key) for My data type.
	 * @param myDt My data type.
	 * @return true if the same named and equivalent data type is found in the result
	 * data type manager.
	 */
	private boolean equivalentDataTypeFound(long myDtID, DataType myDt) {
		if (myResolvedDts.containsKey(myDtID)) {
			return true;
		}
		DataType resultDt = dtms[RESULT].getDataType(myDt.getCategoryPath(), myDt.getName());
		if (resultDt != null) {
			SourceArchive resultSourceArchive = resultDt.getSourceArchive();
			SourceArchive mySourceArchive = myDt.getSourceArchive();
			UniversalID resultDtUniversalID = resultDt.getUniversalID();
			UniversalID myDtUniversalID = myDt.getUniversalID();
			// UniversalID can be null if data type is BuiltIn.
			if (!resultSourceArchive.getSourceArchiveID()
					.equals(mySourceArchive.getSourceArchiveID()) ||
				!Objects.equals(resultDtUniversalID, myDtUniversalID)) {
				return false;
			}
			if (resultDt.isEquivalent(myDt)) {
				myResolvedDts.put(myDtID, resultDt);
				return true;
			}
		}
		return false;
	}

	private void fixUpDataTypes() {
		// fix data types in the fixUpList
		ArrayList<FixUpInfo> unresolvedFixups = new ArrayList<>();

		/**
		 * NOTE: It is important that fixups for a Structure are processed bottom-up
		 * (i.e., last-ordinal to first-ordinal) to ensure that subsequent fixup ordinal
		 * indexes remain valid even after components are removed as a result of processing
		 * a Structure fixup. 
		 */
		Collections.sort(fixUpList);

		for (int i = 0; i < fixUpList.size(); i++) {

			FixUpInfo info = fixUpList.get(i);
			DataType dt = info.ht.get(info.id);
			if (dt instanceof Union) {
				// Fixups for a union are done all at once
				// Determine number of applicable fixups (assumes they are sequential for the same Union)
				int count = 1;
				for (int n = i + 1; n < fixUpList.size(); n++) {
					if (fixUpList.get(n).id != info.id) {
						break;
					}
					++count;
				}
				fixUpUnion(info.id, (Union) dt, i, count, unresolvedFixups);
				i += count - 1;
			}
			else if (dt instanceof Structure struct) {
				if (!fixUpStructure(info, struct)) {
					unresolvedFixups.add(info);
				}
			}
			else if (dt instanceof FunctionDefinition fndef) {
				if (!fixUpFunctionDef(info, fndef)) {
					unresolvedFixups.add(info);
				}
			}
			else {
				DataTypeManager dtm = info.getDataTypeManager();
				if (resolve(info.compID, dtm, info.ht) != null) {
					resolve(info.id, dtm, info.ht);
				}
			}
		}
		// update fixup list with those that were unresolved
		fixUpList = unresolvedFixups;
	}

	private String buildDataTypeFailureComment(DataType dt, String reason, String oldComment) {
		StringBuilder sb = new StringBuilder("Failed to apply '");
		sb.append(dt.getDisplayName());
		sb.append("'");
		if (!StringUtils.isBlank(reason)) {
			sb.append(", ");
			sb.append(reason);
		}
		if (!StringUtils.isBlank(oldComment)) {
			sb.append("; ");
			sb.append(oldComment);
		}
		return sb.toString();
	}

	/**
	 * Fix up the function definition using the fix up info for a component.
	 * @param info fixup info
	 * @param fd function definition to be fixed-up
	 * @return true if fixup successfully processed else false
	 */
	private boolean fixUpFunctionDef(FixUpInfo info, FunctionDefinition fd) {

		DataType dt = resolve(info.compID, info.getDataTypeManager(), info.ht);

		long lastChangeTime = fd.getLastChangeTime(); // Don't let the time change.
		try {
			if (dt != null) {
				if (info.index < 0) { // -1 for return type
					fd.setReturnType(dt);
				}
				else {
					ParameterDefinition[] args = fd.getArguments();
					args[info.index].setDataType(dt);
				}
				return true;
			}

			if (info.index < 0) { // -1 for return type
				// nowhere to set error comment
			}
			else {
				ParameterDefinition[] args = fd.getArguments();
				ParameterDefinition arg = args[info.index];
				String comment =
					buildDataTypeFailureComment(info.componentDataType, null, arg.getComment());
				arg.setComment(comment);
			}
		}
		finally {
			fd.setLastChangeTime(lastChangeTime); // Reset the last change time to the merged data type's.
		}
		return false;
	}

	/**
	 * Process fixup for packed structure component
	 * @param info fixup info
	 * @param struct result structure
	 * @param dt component datatype (may be null if type failed to be resolved)
	 * @return false if component not found, else true
	 */
	private boolean fixUpPackedStructureComponent(FixUpInfo info, Structure struct, DataType dt) {
		int ordinal = info.index;

		DataTypeComponent dtc = null;
		if (ordinal >= 0 || ordinal < struct.getNumComponents()) {
			dtc = struct.getComponent(ordinal);
		}

		if (dtc == null) {
			throw new AssertException("Expected bad datatype placeholder");
		}

		long lastChangeTime = struct.getLastChangeTime(); // Don't let the time change.
		try {
			if (dtc.isBitFieldComponent()) {
				if (info.bitOffset < 0) {
					throw new AssertException("Expected bitfield fixup location");
				}
				if (dt == null || dt.isDeleted()) {
					// bitfield will retain use of the primitive base datatype
					String comment =
						buildDataTypeFailureComment(info.componentDataType, null, dtc.getComment());
					dtc.setComment(comment);
					return false;
				}
				if (BitFieldDataType.isValidBaseDataType(dt)) {
					// replace bitfield base datatype - silent if updated type is not a valid base type
					BitFieldDataType bfDt = (BitFieldDataType) dtc.getDataType();
					struct.delete(ordinal);
					try {
						struct.insertBitField(ordinal, bfDt.getLength(), bfDt.getBitOffset(), dt,
							bfDt.getDeclaredBitSize(), dtc.getFieldName(), dtc.getComment());
						return true;
					}
					catch (InvalidDataTypeException e) {
						// Try again with primitive base type
						DataType primitiveBaseDt = bfDt.getPrimitiveBaseDataType();
						String comment = buildDataTypeFailureComment(info.componentDataType,
							e.getMessage(), dtc.getComment());
						try {
							struct.insertBitField(ordinal, bfDt.getLength(), bfDt.getBitOffset(),
								primitiveBaseDt, bfDt.getDeclaredBitSize(), dtc.getFieldName(),
								comment);
							return true;
						}
						catch (InvalidDataTypeException exc) {
							throw new RuntimeException(exc); // unexpected
						}
					}
				}
			}
			else {
				if (info.bitOffset >= 0) {
					throw new AssertException("Unexpected bitfield fixup location");
				}
				if (dtc.getDataType() != BadDataType.dataType) {
					throw new AssertException("Expected bad datatype placeholder");
				}
				if (dt == null || dt.isDeleted()) {
					String comment =
						buildDataTypeFailureComment(info.componentDataType, null, dtc.getComment());
					dtc.setComment(comment);
					return false;
				}

				// handle non-bitfield component fixup
				int length = dt.getLength();
				if (length <= 0) {
					length = dtc.getLength();
				}
				try {
					struct.replace(ordinal, dt, length, dtc.getFieldName(), dtc.getComment());
					return true;
				}
				catch (IllegalArgumentException e) {
					displayError(struct, e);
					String comment = buildDataTypeFailureComment(info.componentDataType,
						e.getMessage(), dtc.getComment());
					dtc.setComment(comment);
				}
			}
		}
		finally {
			struct.setLastChangeTime(lastChangeTime); // Reset the last change time to the merged data type's.
		}
		return false;
	}

	/**
	 * Process fixup for non-packed structure component
	 * @param info fixup info
	 * @param struct result structure
	 * @param dt component datatype
	 * @return false if component not found, else true
	 */
	private boolean fixUpNonPackedStructureComponent(FixUpInfo info, Structure struct,
			DataType dt) {

		int ordinal = info.index;

		DataTypeComponent dtc = null;
		if (ordinal >= 0 || ordinal < struct.getNumComponents()) {
			dtc = struct.getComponent(ordinal);
		}

		long lastChangeTime = struct.getLastChangeTime(); // Don't let the time change.
		try {
			if (dtc.isBitFieldComponent()) {
				if (info.bitOffset < 0) {
					throw new AssertException("Expected bitfield fixup location");
				}
				if (dt == null || dt.isDeleted()) {
					// bitfield will retain use of the primitive base datatype
					String comment =
						buildDataTypeFailureComment(info.componentDataType, null, dtc.getComment());
					dtc.setComment(comment);
					return false;
				}
				if (BitFieldDataType.isValidBaseDataType(dt)) {
					// replace bitfield base datatype - silent if updated type is not a valid base type
					BitFieldDataType bfDt = (BitFieldDataType) dtc.getDataType();
					struct.delete(ordinal);
					try {
						struct.insertBitFieldAt(dtc.getOffset(), bfDt.getLength(),
							bfDt.getBitOffset(), dt, bfDt.getDeclaredBitSize(), dtc.getFieldName(),
							dtc.getComment());
					}
					catch (InvalidDataTypeException e) {
						// Try again with primitive base type
						DataType primitiveBaseDt = bfDt.getPrimitiveBaseDataType();
						String comment = buildDataTypeFailureComment(info.componentDataType,
							e.getMessage(), dtc.getComment());
						try {
							struct.insertBitFieldAt(dtc.getOffset(), bfDt.getLength(),
								bfDt.getBitOffset(), primitiveBaseDt, bfDt.getDeclaredBitSize(),
								dtc.getFieldName(), comment);
						}
						catch (InvalidDataTypeException exc) {
							throw new RuntimeException(exc); // unexpected
						}
					}
				}
			}
			else {
				if (info.bitOffset >= 0) {
					throw new AssertException("Unexpected bitfield fixup location");
				}
				if (dtc.getDataType() != BadDataType.dataType) {
					throw new AssertException("Expected bad datatype placeholder");
				}
				if (dt == null || dt.isDeleted()) {
					String comment =
						buildDataTypeFailureComment(info.componentDataType, null, dtc.getComment());
					dtc.setComment(comment);
					return false;
				}

				// handle non-bitfield component fixup
				int offset = dtc.getOffset();
				int dtcLength = dtc.getLength();
				int length = dt.getLength();
				if (length <= 0) {
					length = dtcLength;
				}
				int bytesNeeded = length - dtcLength;
				if (bytesNeeded > 0) {
					int nextOffset = offset + dtcLength;
					DataTypeComponent nextDefinedDtc =
						struct.getDefinedComponentAtOrAfterOffset(nextOffset);
					if (nextDefinedDtc != null) {
						int bytesAvailable = nextDefinedDtc.getOffset() - nextOffset;
						if (bytesAvailable < bytesNeeded) {
							// The data type is too big, so adjust the component length to what will fit.
							length = dtcLength + bytesAvailable;
							// Output a warning indicating the structure has a data type that doesn't fit.
							String message = "Structure Merge: Not enough undefined bytes to fit " +
								dt.getPathName() + " in structure " + struct.getPathName() +
								" at offset 0x" + Integer.toHexString(offset) + "." +
								"\nIt needs " + (bytesNeeded - bytesAvailable) +
								" more byte(s) to be able to fit.";
							Msg.warn(this, message);
						}
					}
				}
				try {
					struct.replaceAtOffset(offset, dt, length, dtc.getFieldName(),
						dtc.getComment());
				}
				catch (IllegalArgumentException e) {
					displayError(struct, e);
					String comment = buildDataTypeFailureComment(info.componentDataType,
						e.getMessage(), dtc.getComment());
					dtc.setComment(comment);
				}
			}
		}
		finally {
			struct.setLastChangeTime(lastChangeTime); // Reset the last change time to the merged data type's.
		}
		return true;
	}

	/**
	 * Fix up the structure using the fix up info for a component.
	 * @param info fixup info
	 * @param struct structure to be fixed-up
	 * @return true if fixup successfully processed else false
	 */
	private boolean fixUpStructure(FixUpInfo info, Structure struct) {

		DataType compDt = resolve(info.compID, info.getDataTypeManager(), info.ht);
		if (struct.isPackingEnabled()) {
			if (fixUpPackedStructureComponent(info, struct, compDt)) {
				return true;
			}
		}
		else if (fixUpNonPackedStructureComponent(info, struct, compDt)) {
			return true;
		}

		String loc;
		if (struct.isPackingEnabled()) {
			loc = "ordinal " + info.index;
		}
		else {
			loc = "offset 0x" + Integer.toHexString(info.offset);
		}
		Msg.warn(this, "Structure Merge: Failed to resolve data type '" +
			info.componentDataType.getName() + "' at " + loc + " in " + struct.getPathName());
		return false; // Don't remove this FixUpInfo from the fixupList so the user will get notified.
	}

	private boolean fixUpUnionComponent(Union union, FixUpInfo info) {

		DataType compDt = resolve(info.compID, info.getDataTypeManager(), info.ht);

		int ordinal = info.index;

		DataTypeComponent dtc = null;
		if (ordinal >= 0 && ordinal <= union.getNumComponents()) {
			dtc = union.getComponent(ordinal);
		}

		if (dtc == null) {
			throw new AssertException("Expected bad datatype placeholder");
		}

		if (dtc.isBitFieldComponent()) {
			if (info.bitOffset < 0) {
				throw new AssertException("Expected bitfield fixup location");
			}
			if (compDt == null || compDt.isDeleted()) {
				// bitfield will retain use of the primitive base datatype
				String comment =
					buildDataTypeFailureComment(info.componentDataType, null, dtc.getComment());
				dtc.setComment(comment);
			}
			else if (BitFieldDataType.isValidBaseDataType(compDt)) {
				// replace bitfield base datatype - silent if updated type is not a valid base type
				BitFieldDataType bfDt = (BitFieldDataType) dtc.getDataType();
				union.delete(ordinal);
				try {
					union.insertBitField(ordinal, compDt, bfDt.getDeclaredBitSize(),
						dtc.getFieldName(), dtc.getComment());
					return true;
				}
				catch (InvalidDataTypeException e) {
					// should never occur
					Msg.error(this, "Unexpected datatype merge fixup error", e);
				}
			}
		}
		else {
			if (info.bitOffset >= 0) {
				throw new AssertException("Unexpected bitfield fixup location");
			}
			if (dtc.getDataType() != BadDataType.dataType) {
				throw new AssertException("Expected bad datatype placeholder");
			}
			if (compDt == null || compDt.isDeleted()) {
				String comment =
					buildDataTypeFailureComment(info.componentDataType, null, dtc.getComment());
				dtc.setComment(comment);
				return false;
			}

			// handle non-bitfield component fixup
			int length = compDt.getLength();
			if (length <= 0) {
				length = dtc.getLength();
			}
			union.delete(ordinal);
			try {
				union.insert(ordinal, compDt, length, dtc.getFieldName(), dtc.getComment());
				return true;
			}
			catch (IllegalArgumentException e) {
				displayError(union, e);
				// restore bad placeholder component
				String comment =
					buildDataTypeFailureComment(info.componentDataType, null, dtc.getComment());
				union.insert(ordinal, BadDataType.dataType, dtc.getLength(), dtc.getFieldName(),
					comment);
			}
		}
		Msg.warn(this,
			"Union Merge: Failed to resolve data type '" + info.componentDataType.getName() +
				"' at ordinal " + info.index + " in " + union.getPathName());
		return false;
	}

	/**
	 * Fix up the Union by going through all of the fix up info objects that
	 * have the given ID.
	 * @param id id of the Union
	 * @param union union that is updated
	 * @param firstFixupIndex first applicable fixupList entry index
	 * @param fixupCount total number of fixup entries to be applied
	 * @param unresolvedFixups list to which unprocessed fixups should be added
	 */
	private void fixUpUnion(long id, Union union, int firstFixupIndex, int fixupCount,
			ArrayList<FixUpInfo> unresolvedFixups) {

		long lastChangeTime = union.getLastChangeTime(); // Don't let the time change.
		try {
			// Process all fixups for union
			int endIndex = firstFixupIndex + fixupCount;
			for (int i = firstFixupIndex; i < endIndex; i++) {
				FixUpInfo info = fixUpList.get(i); // assume info applies to union
				if (!fixUpUnionComponent(union, info)) {
					Msg.warn(this, "Union Merge: Failed to apply data type at ordinal " +
						info.index + " in " + union.getPathName());
					unresolvedFixups.add(info);
				}
			}
		}
		finally {
			union.setLastChangeTime(lastChangeTime); // Reset the last change time to the merged data type's.
		}
	}

	private DataType resolve(long id, DataTypeManager dtm,
			MyIdentityHashMap<Long, DataType> resolvedDataTypes) {

		DataType dt = getResolvedComponent(id, resolvedDataTypes);
		if (dt == null && resolvedDataTypes.containsKey(id)) {
			// previously resolved datatype is no longer valid
			return null;
		}

		if (dt == null && !myDtAddedList.contains(Long.valueOf(id))) {
			// use data type from RESULT if we did not add it
			dt = dtms[RESULT].getDataType(id);
		}

		if (dt == null) {
			DataType otherDt = dtm.getDataType(id);
			if (otherDt instanceof BuiltIn) {
				return otherDt; // don't let deleted BuiltIn stop us fro using one
			}
			boolean doCheck = false;
			DataType baseDt = otherDt;
			if (baseDt instanceof TypeDef td) {
				baseDt = td.getDataType();
				long baseID = dtm.getID(baseDt);
				if (!myDtAddedList.contains(Long.valueOf(baseID))) {
					return null; // pre-existing typedef was removed
				}
				doCheck = true;
			}
			if ((baseDt instanceof Pointer) || (baseDt instanceof Array)) {
				baseDt = DataTypeUtilities.getBaseDataType(baseDt);
				doCheck = true;
			}

			if (doCheck) {
				long baseID = dtm.getID(baseDt);
				DataType rdt = resolve(baseID, dtm, resolvedDataTypes);
				if ((rdt != null && !rdt.isDeleted()) || (baseDt instanceof BuiltIn)) {
					// base data type was resolved or is BuiltIn/DEFAULT, so add derived datatype
					dt = addDataType(id, otherDt, resolvedDataTypes);
				}
			}
		}
		if (dt != null && dt.isDeleted()) {
			return null;
		}
		return dt;
	}

	private void processDataTypeSourceChanged(long id) {
		if (dataTypeSourceWasChanged(id, dtms[MY])) {
			updateDataTypeSource(id, dtms[MY], myResolvedDts);
		}
	}

	private void processDataTypeRenamed(long id) {
		DataType myDt = dtms[MY].getDataType(id);
		DataType dt = dtms[RESULT].getDataType(id);
		if (dataTypeWasRenamed(id, dtms[MY])) {
			if (dt != null) {
				setDataTypeName(dt, myDt);
			}
		}
	}

	private void processDataTypeEdited(long id) {
		if (dataTypeWasChanged(id, dtms[MY])) {
			updateDataType(id, dtms[MY], myResolvedDts, false);
		}
	}

	private void processDataTypeDeleted(long myDtID) {
		// Note: The ID passed to this method can be a changed or deleted data type.
		// My deleted data types will not be in My data type manager.
		DataType myDt = dtms[MY].getDataType(myDtID);
		if (myDt == null) {
			myDt = dtms[RESULT].getDataType(myDtID);
			// My deleted data types will be in the result unless the latest already deleted it.
			if (myDt != null) {
				// If it's still in the result remove it.
				dtms[RESULT].remove(myDt, currentMonitor);
			}
		}
	}

	private void processDataTypeMoved(long id) {
		if (dataTypeWasMoved(id, dtms[MY])) {
			DataType myDt = dtms[MY].getDataType(id);
			CategoryPath myParentPath = myDt.getCategoryPath();

			DataType resultDt = dtms[RESULT].getDataType(id);
			if (!myParentPath.equals(resultDt.getCategoryPath())) {
				Category resultParent = dtms[RESULT].createCategory(myParentPath);
				try {
					resultParent.moveDataType(resultDt, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DataTypeDependencyException e) {
					String msg = "Move data type named " + resultDt.getName() +
						" failed.\nProblem: " + e.getMessage();
					MergeManager.showBlockingError("Error Moving Data Type", msg);
				}
			}
		}
	}

	/**
	 * Determines myDtChangeList, myDtAddedList, dtConflictList and number of data type conflicts
	 * <br>- myDtChangeList = My data types that changed and are not in conflict.
	 * <br>- myDtAddedList = My data types that were added and are not in conflict.
	 * <br>- dtConflictList = conflicting categories where My and Latest both changed the data type.
	 * @param latestChanges data type changes for the Latest domain object
	 * @param myChanges data type changes for My domain object
	 */
	private void setupSourceArchiveChanges(DataTypeChangeSet latestChanges,
			DataTypeChangeSet myChanges) {

		// Source Archives
		long[] latestArchiveChanges = latestChanges.getSourceArchiveChanges();
		long[] latestArchiveAdds = latestChanges.getSourceArchiveAdditions();
		Arrays.sort(latestArchiveChanges);
		Arrays.sort(latestArchiveAdds);
		long[] myArchiveChanges = myChanges.getSourceArchiveChanges();
		long[] myArchiveAdds = myChanges.getSourceArchiveAdditions();

		dirtyMap = new HashMap<>();

		archiveConflictList = new ArrayList<>();
		myArchiveChangeList = new ArrayList<>();
		myArchiveAddedList = new ArrayList<>();

		// Determine which source archive adds are in conflict.
		determineSourceArchiveAddConflicts(latestArchiveAdds, myArchiveAdds);

		// Determine which source archive changes are in conflict.
		determineSourceArchiveChangeConflicts(latestArchiveChanges, myArchiveChanges);

		totalConflictCount += archiveConflictList.size();
	}

	private void determineSourceArchiveChangeConflicts(long[] latestArchiveChanges,
			long[] myArchiveChanges) {
		for (long myChangeID : myArchiveChanges) {
			UniversalID sourceID = new UniversalID(myChangeID);
			Long myChangeIDObject = Long.valueOf(myChangeID);
			if (myArchiveAddedList.contains(myChangeIDObject) ||
				archiveConflictList.contains(myChangeIDObject)) {
				continue;
			}

			SourceArchive mySourceArchive = dtms[MY].getSourceArchive(sourceID);
			loadDirtyMap(sourceID, mySourceArchive);

			int searchIndex = Arrays.binarySearch(latestArchiveChanges, myChangeID);
			boolean changedInLatest = (searchIndex >= 0);
			if (changedInLatest) {
				SourceArchive origSourceArchive = dtms[ORIGINAL].getSourceArchive(sourceID);
				if (origSourceArchive == null) {
					// No source means both added and then changed.
					// Shouldn't get here but if we do then let add handle it.
					continue;
				}
				SourceArchive latestSourceArchive = dtms[LATEST].getSourceArchive(sourceID);
				boolean removedMy = mySourceArchive == null;
				boolean removedLatest = latestSourceArchive == null;
				if (removedMy && removedLatest) {
					continue; // Both removed source archive.
				}
				if (removedMy || removedLatest) {
					// Remove in one conflicts with change in other.
					archiveConflictList.add(myChangeIDObject);
					continue;
				}

				String origName = origSourceArchive.getName();
				String latestName = latestSourceArchive.getName();
				String myName = mySourceArchive.getName();

				boolean sameName = StringUtils.equals(myName, latestName);
				boolean latestChangedName = !StringUtils.equals(origName, latestName);
				boolean myChangedName = !StringUtils.equals(origName, myName);
				// Neither removed the source archive so see what changed.
				if (!sameName && latestChangedName && myChangedName) {
					archiveConflictList.add(myChangeIDObject);
					continue;
				}
			}
			myArchiveChangeList.add(Long.valueOf(myChangeID));
		}
	}

	private void determineSourceArchiveAddConflicts(long[] latestArchiveAdds,
			long[] myArchiveAdds) {
		for (long myAddID : myArchiveAdds) {
			UniversalID sourceID = new UniversalID(myAddID);
			SourceArchive mySourceArchive = dtms[MY].getSourceArchive(sourceID);
			if (mySourceArchive == null) {
				continue; // source archive was added and then removed.
			}

			loadDirtyMap(sourceID, mySourceArchive);

			boolean foundConflict = false;
			for (long latestAddID : latestArchiveAdds) {
				if (myAddID == latestAddID) {
					SourceArchive latestSourceArchive =
						dtms[LATEST].getSourceArchive(new UniversalID(latestAddID));
					if (!StringUtils.equals(mySourceArchive.getName(),
						latestSourceArchive.getName())) {
						archiveConflictList.add(Long.valueOf(myAddID));
						foundConflict = true;
						break;
					}
				}
			}
			if (!foundConflict) {
				myArchiveAddedList.add(Long.valueOf(myAddID));
			}
		}
	}

	private void loadDirtyMap(UniversalID sourceID, SourceArchive mySourceArchive) {
		if (mySourceArchive == null) {
			return;
		}
		if (!dirtyMap.containsKey(sourceID)) {
			SourceArchive latestSourceArchive = dtms[LATEST].getSourceArchive(sourceID);
			boolean latestDirty =
				(latestSourceArchive != null) ? latestSourceArchive.isDirty() : false;
			boolean myDirty = mySourceArchive.isDirty();
			dirtyMap.put(sourceID, Boolean.valueOf(myDirty || latestDirty));
		}
	}

	/**
	 * Determines myDtChangeList, myDtAddedList, dtConflictList and number of data type conflicts
	 * <br>- myDtChangeList = My data types that changed and are not in conflict.
	 * <br>- myDtAddedList = My data types that were added and are not in conflict.
	 * <br>- dtConflictList = conflicting categories where My and Latest both changed the data type.
	 * @param latestChanges data type changes for the Latest domain object
	 * @param myChanges data type changes for My domain object
	 */
	private void setupDataTypeChanges(DataTypeChangeSet latestChanges,
			DataTypeChangeSet myChanges) {

		// Data Types
		long[] latestDtChanges = latestChanges.getDataTypeChanges();
		long[] latestDtAdds = latestChanges.getDataTypeAdditions();
		long[] myDtChanges = myChanges.getDataTypeChanges();
		long[] myDtAdds = myChanges.getDataTypeAdditions();

		dtConflictList = new ArrayList<>();
		dtSourceConflictList = new ArrayList<>();
		myDtChangeList = new ArrayList<>();
		for (long myDtChange : myDtChanges) {
			myDtChangeList.add(Long.valueOf(myDtChange));
		}

		processAddIDs(myDtAdds);

		ArrayList<Long> resultDtChangeList = new ArrayList<>();
		for (long latestDtChange : latestDtChanges) {
			resultDtChangeList.add(Long.valueOf(latestDtChange));
		}
		ArrayList<Long> resultDtAddList = new ArrayList<>();
		for (long latestDtAdd : latestDtAdds) {
			resultDtAddList.add(Long.valueOf(latestDtAdd));
		}
		// remove my Added dt's from my changed dt's
		// Added and then changed data types should only be in added.
		myDtChangeList.removeAll(myDtAddedList);
		myDtChangeList.removeAll(dtConflictList);

		dtConflictList.addAll(myDtChangeList);
		// automatic = my changes - latest changes
		// (any id in my changes and not in the latest is not a conflict)
		myDtChangeList.removeAll(resultDtChangeList);

		// get conflicting IDs where Latest and My both changed data type.
		ArrayList<Long> resultDtCombinedList = new ArrayList<>();
		resultDtCombinedList.addAll(resultDtChangeList);
		resultDtCombinedList.addAll(resultDtAddList);
		// Changed this to use combined list so that add conflicts don't get discarded.
		dtConflictList.retainAll(resultDtCombinedList);
		resultDtCombinedList = null;

		eliminateFakeConflicts();

		origDtConflictList = new ArrayList<>(dtConflictList);

		myResolvedDts = new MyIdentityHashMap<>();
		latestResolvedDts = new MyIdentityHashMap<>();
		origResolvedDts = new MyIdentityHashMap<>();

		fixUpList = new ArrayList<>();
		fixUpIDSet = new HashSet<>();
		totalConflictCount += dtConflictList.size();

	}

	/**
	 * Processes my data types that were added and determines whether each is actually a
	 * conflict, an added data type, or a changed data type relative to the Latest check in.
	 * @param myDtAdds the data type IDs
	 */
	private void processAddIDs(long[] myDtAdds) {
		myDtAddedList = new ArrayList<>();
		for (long myDtAdd : myDtAdds) {
			DataType myDt = dtms[MY].getDataType(myDtAdd);
			if (myDt != null) {
				SourceArchive sourceArchive = myDt.getSourceArchive();
				UniversalID dataTypeID = myDt.getUniversalID();
				DataType resultDt =
					(dataTypeID != null) ? dtms[RESULT].getDataType(sourceArchive, dataTypeID)
							: null;
				if (resultDt != null) {
					if (!resultDt.getCategoryPath().equals(myDt.getCategoryPath()) ||
						!DataTypeUtilities.equalsIgnoreConflict(resultDt.getName(),
							myDt.getName()) ||
						!resultDt.isEquivalent(myDt)) {
						dtConflictList.add(Long.valueOf(myDtAdd));
						dtSourceConflictList.add(Long.valueOf(myDtAdd));
						continue;
					}
				}
				myDtAddedList.add(Long.valueOf(myDtAdd));
			}
			else { // Added and then removed data types go on the change list.
				Long l = Long.valueOf(myDtAdd);
				if (!myDtChangeList.contains(l)) {
					myDtChangeList.add(l);
				}
			}
		}
	}

	private void eliminateFakeConflicts() {
		// remove conflicts that are not really conflicts
		for (int i = 0; i < dtConflictList.size(); i++) {
			long id = dtConflictList.get(i).longValue();
			DataType myDt = dtms[MY].getDataType(id);
			if ((myDt instanceof Pointer) || (myDt instanceof Array)) {
				dtConflictList.remove(i);
				--i;
				continue;
			}

			if (myDt == null) {
				DataType latestDt = dtms[LATEST].getDataType(id);
				if ((latestDt instanceof Pointer) || (latestDt instanceof Array)) {
					dtConflictList.remove(i);
					--i;
					continue;
				}
			}

			boolean renamedMy = dataTypeWasRenamed(id, dtms[MY]) || dataTypeWasMoved(id, dtms[MY]);
			boolean renamedLatest =
				dataTypeWasRenamed(id, dtms[LATEST]) || dataTypeWasMoved(id, dtms[LATEST]);
			boolean myChanged = dataTypeWasChanged(id, dtms[MY]);
			boolean latestChanged = dataTypeWasChanged(id, dtms[LATEST]);
			boolean sameSource = !dataTypeSourceWasChanged(id, dtms[LATEST], dtms[MY]);
			boolean mySourceChanged = sameSource ? false : dataTypeSourceWasChanged(id, dtms[MY]);
			boolean latestSourceChanged =
				sameSource ? false : dataTypeSourceWasChanged(id, dtms[LATEST]);
			boolean wasDeleted =
				dataTypeWasDeleted(id, dtms[MY]) || dataTypeWasDeleted(id, dtms[LATEST]);
			// if LATEST and MY are the same, then treat this as
			// no changes were made to either
			if (!dataTypeWasDeleted(id, dtms[MY]) && !dataTypeWasDeleted(id, dtms[LATEST]) &&
				!dataTypeWasChanged(id, dtms[LATEST], dtms[MY])) {
				myChanged = false;
				latestChanged = false;
			}
			// if names are the same and paths are the same, then treat
			// this as not renamed or moved in either
			if (!wasDeleted && !dataTypeWasRenamed(id, dtms[LATEST], dtms[MY]) &&
				!dataTypeWasMoved(id, dtms[LATEST], dtms[MY])) {
				renamedMy = false;
				renamedLatest = false;
			}

			if (dtSourceConflictList.contains(id)) {
				// This is a source data type based conflict.
				continue;
			}
			if ((renamedMy && renamedLatest) || (renamedMy && wasDeleted) ||
				(renamedLatest && wasDeleted) || (myChanged && latestChanged) ||
				((myChanged || latestChanged) && wasDeleted) ||
				(mySourceChanged && latestSourceChanged) ||
				((mySourceChanged || latestSourceChanged) && wasDeleted)) {

				// still a conflict
				continue;
			}
			// If renamed in my and changed in latest or vice versa then not a conflict.
			// Just need the change from My.
			dtConflictList.remove(i);
			if (myChanged || renamedMy || mySourceChanged) {
				myDtChangeList.add(Long.valueOf(id));
			}
			--i;
		}
		Collections.sort(dtConflictList);
	}

	/**
	 * Determines myCatChangeList, myCatAddedList, catConflictList and number of category conflicts
	 * <br>- myCatChangeList = My categories that changed and are not in conflict.
	 * <br>- myCatAddedList = Latest categories that changed and are not in conflict.
	 * <br>- catConflictList = conflicting categories where My and Latest both changed the category.
	 * @param latestChanges category changes for the Latest domain object
	 * @param myChanges category changes for My domain object
	 */
	private void setupCategoryChanges(DataTypeChangeSet latestChanges,
			DataTypeChangeSet myChanges) {

		// Categories

		myCatChangeList = new ArrayList<>();
		long[] myCatChanges = myChanges.getCategoryChanges();
		Arrays.sort(myCatChanges);
		for (long myCatChange : myCatChanges) {
			myCatChangeList.add(Long.valueOf(myCatChange));
		}

		myCatAddedList = new ArrayList<>();
		long[] myCatAdds = myChanges.getCategoryAdditions();
		Arrays.sort(myCatAdds);
		for (long myCatAdd : myCatAdds) {
			if (dtms[MY].getCategory(myCatAdd) != null) {
				myCatAddedList.add(Long.valueOf(myCatAdd));
			}
			else { // Added and then removed categories go on the change list.
				Long l = Long.valueOf(myCatAdd);
				if (!myCatChangeList.contains(l)) {
					myCatChangeList.add(l);
				}
			}
		}
		Collections.sort(myCatChangeList);

		long[] latestCatChanges = latestChanges.getCategoryChanges();
		Arrays.sort(latestCatChanges);
		ArrayList<Long> resultCatChangeList = new ArrayList<>();
		for (long latestCatChange : latestCatChanges) {
			resultCatChangeList.add(Long.valueOf(latestCatChange));
		}
		// remove my Added categories from my changed categories
		// Added and then changed categories should only be in added.
		myCatChangeList.removeAll(myCatAddedList);

		catConflictList = new ArrayList<>(myCatChangeList);
		//	automatic = my changes - latest changes
		// (any id in my changes and not in the latest is not a conflict)
		myCatChangeList.removeAll(resultCatChangeList);

		// get conflicting IDs where Latest and My both changed category.
		catConflictList.retainAll(resultCatChangeList);

		for (int i = 0; i < catConflictList.size(); i++) {
			long id = catConflictList.get(i).longValue();

			// If Latest and My both removed a category then it isn't in conflict.
			if (dtms[MY].getCategory(id) == null && dtms[LATEST].getCategory(id) == null) {

				catConflictList.remove(i);
				--i;
				continue;
			}

			boolean renamedMy = categoryWasRenamed(id, dtms[MY]) || categoryWasMoved(id, dtms[MY]);
			boolean renamedLatest =
				categoryWasRenamed(id, dtms[LATEST]) || categoryWasMoved(id, dtms[LATEST]);
			boolean wasDeleted =
				dtms[MY].getCategory(id) == null || dtms[LATEST].getCategory(id) == null;

			if (dtms[MY].getCategory(id) != null && dtms[LATEST].getCategory(id) != null &&
				!categoryWasRenamed(id, dtms[MY], dtms[LATEST]) &&
				!categoryWasMoved(id, dtms[MY], dtms[LATEST])) {
				renamedMy = false;
				renamedLatest = false;
			}
			if ((renamedMy && renamedLatest) || (renamedMy && wasDeleted) ||
				(renamedLatest && wasDeleted)) {

				// still a conflict
				continue;
			}
			if (renamedMy) { // Renamed My category without conflict.
				myCatChangeList.add(Long.valueOf(id));
			}
			catConflictList.remove(i); // remove ID from conflicts since not actually in conflict.
			--i;
		}
		totalConflictCount += catConflictList.size();
	}

	private void resetOption() {
		if (mergeManager != null) {
			conflictOption = originalConflictOption;
		}
	}

	@Override
	public String[][] getPhases() {
		return new String[][] { DATA_TYPES_PHASE };
	}

	private DataTypeManager getDataTypeManager(Map<Long, DataType> dataTypeMap) {
		if (dataTypeMap == origResolvedDts) {
			return dtms[ORIGINAL];
		}
		if (dataTypeMap == latestResolvedDts) {
			return dtms[RESULT];
		}
		return dtms[MY];
	}

	/**
	 * FixUpInfo objects that must be resolved after
	 * data types have been added and conflicts resolved.
	 */
	private class FixUpInfo implements Comparable<FixUpInfo> {

		final long id;
		final long compID;
		final DataType componentDataType;
		final int index;
		final MyIdentityHashMap<Long, DataType> ht;

		// component offset - for display/logging use only
		// only meaningful for non-packed structure
		// may not be unique (e.g., bitfields, 0-length components)
		int offset = -1;

		// bitfield info
		int bitOffset = -1;
		int bitSize = -1;

		/**
		 * Construct info needed to fix up data types after base types
		 * or components were resolved.
		 * @param id source data type ID needing to be fixed up
		 * @param compID source datatype ID of either param/component or bitfield base type
		 * @param componentDataType source component/dependency datatype
		 * @param index offset into non-packed structure, or ordinal into union or packed
		 * structure; or parameter/return ordinal; for other data types index is not used (specify -1).
		 * @param resolvedDataTypes hashtable used for resolving the data type
		 */
		FixUpInfo(long id, long compID, DataType componentDataType, int index,
				MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
			this.id = id;
			this.compID = compID;
			this.componentDataType = componentDataType;
			this.index = index;
			this.ht = resolvedDataTypes;

			if (componentDataType instanceof BitFieldDataType) {
				throw new IllegalArgumentException(
					"BitFieldDataType not allowed - base type expected");
			}
		}

		/**
		 * Construct info needed to fix up data types after base types
		 * or components were resolved.
		 * @param id id of data type needing to be fixed up
		 * @param compID datatype ID of either param/component or bitfield base type
		 * @param destOrdinal component ordinal within destination composite
		 * @param sourceDtc associated composite datatype component
		 * @param resolvedDataTypes hashtable used for resolving the data type
		 */
		FixUpInfo(long id, long compID, int destOrdinal, DataTypeComponent sourceDtc,
				MyIdentityHashMap<Long, DataType> resolvedDataTypes) {
			this(id, compID, getDataType(sourceDtc), destOrdinal, resolvedDataTypes);
			offset = sourceDtc.getOffset();
			if (sourceDtc.isBitFieldComponent()) {
				BitFieldDataType bfDt = (BitFieldDataType) sourceDtc.getDataType();
				bitSize = bfDt.getDeclaredBitSize();
				bitOffset = bfDt.getBitOffset();
			}
		}

		private static DataType getDataType(DataTypeComponent sourceDtc) {
			DataType dt = sourceDtc.getDataType();
			if (dt instanceof BitFieldDataType bfDt) {
				dt = bfDt.getBaseDataType();
			}
			return dt;
		}

		@Override
		public int compareTo(FixUpInfo o) {
			// Compare such that items are grouped by id and sort such that the greatest index
			// is first within that group.
			long c = id - o.id;
			if (c == 0) {
				c = Integer.toUnsignedLong(o.index) - Integer.toUnsignedLong(index);
			}
			if (c == 0) {
				return 0;
			}
			return c < 0 ? -1 : 1;
		}

		@Override
		public String toString() {
			String htStr = "MY";
			DataTypeManager dtm = dtms[MY];
			if (ht == origResolvedDts) {
				htStr = "ORIGINAL";
				dtm = dtms[ORIGINAL];
			}
			else if (ht == latestResolvedDts) {
				htStr = "LATEST/RESULTS";
				dtm = dtms[LATEST];
			}
			String bitInfo = "";
			if (bitOffset >= 0) {
				bitInfo = "\nbitOffset=" + bitOffset + ",\nbitSize = " + bitSize + ",\n";
			}
			return "\n" + "ID = " + Long.toHexString(id) + ",\ndt = " + dtm.getDataType(id) +
				",\ncomponent ID = " + Long.toHexString(compID) + ",\ncomponent dt = " +
				dtm.getDataType(compID) + ",\noffset/index = " + index + ",\n" + bitInfo + "ht = " +
				htStr + "\n";
		}

		DataTypeManager getDataTypeManager() {
			if (ht == origResolvedDts) {
				return dtms[ORIGINAL];
			}
			if (ht == latestResolvedDts) {
				return dtms[RESULT];
			}
			return dtms[MY];
		}
	}

	/**
	 * <code>MyIdentityHashMap</code> extends {@link HashMap} with the only difference being its 
	 * implementation of {@link #hashCode()} and {@link #equals(Object)} which are based purely on 
	 * the map instance identity and not its content.
	 * <p>
	 * This unique implementation was created due to the use of this map as a key within another
	 * {@code Map}.
	 */
	private static class MyIdentityHashMap<K, V> extends HashMap<K, V> {

		@Override
		public int hashCode() {
			return System.identityHashCode(this);
		}

		@Override
		public boolean equals(Object o) {
			return o == this;
		}
	}

}
