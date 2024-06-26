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
package ghidra.app.plugin.core.datamgr;

import java.awt.FontMetrics;
import java.util.*;
import java.util.function.Consumer;

import javax.swing.JLabel;
import javax.swing.SwingUtilities;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.label.GDHtmlLabel;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.html.HTMLDataTypeRepresentation;
import ghidra.app.util.html.MissingArchiveDataTypeHTMLRepresentation;
import ghidra.program.database.data.*;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.*;
import utility.function.ExceptionalConsumer;

/**
 * Class for performing basic functions related to synchronizing data types between a program and
 * an archive.
 */
public class DataTypeSynchronizer {

	private final DataTypeManager dataTypeManager;
	private final SourceArchive sourceArchive;
	private final DataTypeManager sourceDTM;

	/**
	 * Creates a DataTypeSynchronizer to be used for synchronizing data types between a program
	 * and an archive.
	 * @param dataTypeManagerHandler the handler that manages all the open data type managers
	 * whether built-in, program, project data type archive or file data type archive.
	 * @param dataTypeManager the program data type manager.
	 * @param source the data type source archive information indicating the associated archive for
	 * synchronizing.
	 */
	public DataTypeSynchronizer(DataTypeManagerHandler dataTypeManagerHandler,
			DataTypeManager dataTypeManager, SourceArchive source) {
		this.dataTypeManager = dataTypeManager;
		this.sourceArchive = source;
		this.sourceDTM = dataTypeManagerHandler.getDataTypeManager(source);
	}

	public List<DataTypeSyncInfo> findOutOfSynchDataTypes() {

		List<DataType> dataTypes = dataTypeManager.getDataTypes(sourceArchive);

		List<DataTypeSyncInfo> dataTypeSyncInfo = new ArrayList<>();
		for (DataType dt : dataTypes) {
			DataTypeSyncInfo syncInfo = new DataTypeSyncInfo(dt, sourceDTM);
			if (syncInfo.canCommit() || syncInfo.canUpdate()) {
				dataTypeSyncInfo.add(syncInfo);
			}
		}
		return dataTypeSyncInfo;
	}

	public List<DataTypeSyncInfo> findAssociatedDataTypes() {
		List<DataType> dataTypes = dataTypeManager.getDataTypes(sourceArchive);

		List<DataTypeSyncInfo> dataTypeSyncInfo = new ArrayList<>();
		for (DataType dt : dataTypes) {
			dataTypeSyncInfo.add(new DataTypeSyncInfo(dt, sourceDTM));
		}
		return dataTypeSyncInfo;
	}

	private static void commit(DataTypeManager sourceDTM, DataType refDT) {
		DataTypeManager refDTM = refDT.getDataTypeManager();
		int sourceTransactionID = sourceDTM.startTransaction("Commit Datatype Changes");
		int refTransactionID = refDTM.startTransaction("Update DataType Sync Time");
		try {
			commitAssumingTransactionsOpen(sourceDTM, refDT);
		}
		finally {
			refDTM.endTransaction(refTransactionID, true);
			sourceDTM.endTransaction(sourceTransactionID, true);
		}
	}

	private static void update(DataTypeManager refDTM, DataType sourceDT) {
		int transactionID = refDTM.startTransaction("Update Datatype " + sourceDT.getName());
		try {
			updateAssumingTransactionsOpen(refDTM, sourceDT);
		}
		finally {
			refDTM.endTransaction(transactionID, true);
		}
	}

	static void commitAssumingTransactionsOpen(DataTypeManager sourceDTM, DataType refDT) {

		// Must refresh associations of refDt and its dependencies to ensure that any
		// non-sourced datatype is properly associated to the sourceDTM
		DataTypeManager refDTM = refDT.getDataTypeManager();
		SourceArchive sourceArchive = refDTM.getSourceArchive(sourceDTM.getUniversalID());
		refDTM.associateDataTypeWithArchive(refDT, sourceArchive);

		// Perform commit of changes by re-resolving and performing additional updates
		// not handled by resolve.
		long lastChangeTime = refDT.getLastChangeTime();
		DataType sourceDT = sourceDTM.resolve(refDT, DataTypeConflictHandler.REPLACE_HANDLER);
		if (!isPointerOrArray(refDT)) {
			if (!namesAreEquivalent(refDT, sourceDT)) {
				renameDataType(sourceDTM, sourceDT, refDT);
			}
			if (!StringUtils.equals(refDT.getDescription(), sourceDT.getDescription())) {
				sourceDT.setDescription(refDT.getDescription());
			}
		}
		sourceDT.setLastChangeTime(lastChangeTime);
		refDT.setLastChangeTimeInSourceArchive(lastChangeTime);
	}

	static void updateAssumingTransactionsOpen(DataTypeManager refDTM, DataType sourceDT) {
		long lastChangeTime = sourceDT.getLastChangeTime();
		DataType refDT = refDTM.resolve(sourceDT, DataTypeConflictHandler.REPLACE_HANDLER);
		if (!isPointerOrArray(sourceDT)) {
			if (!namesAreEquivalent(refDT, sourceDT)) {
				renameDataType(refDTM, refDT, sourceDT);
			}
			if (!StringUtils.equals(sourceDT.getDescription(), refDT.getDescription())) {
				refDT.setDescription(sourceDT.getDescription());
			}
		}
		refDT.setLastChangeTimeInSourceArchive(lastChangeTime);
		refDT.setLastChangeTime(lastChangeTime);
	}

	/**
	 * Commits a single program data type's changes to the associated source data type in the
	 * archive.
	 * @param dtmHandler the handler that manages data types
	 * @param dt the program data type
	 * @return true if the commit succeeds
	 */
	public static boolean commit(DataTypeManagerHandler dtmHandler, DataType dt) {
		SourceArchive sourceArchive = dt.getSourceArchive();
		DataTypeManager sourceDTM = dtmHandler.getDataTypeManager(sourceArchive);
		if (sourceDTM == null) {
			return false;
		}
		commit(sourceDTM, dt);
		return true;
	}

	/**
	 * Updates a single data type in the program to match the associated source data type from the
	 * archive.
	 * @param dtmHandler the handler that manages data types
	 * @param dt the data type
	 * @return true if the update succeeds
	 */
	public static boolean update(DataTypeManagerHandler dtmHandler, DataType dt) {
		DataTypeManager dataTypeManager = dt.getDataTypeManager();
		SourceArchive sourceArchive = dt.getSourceArchive();
		DataTypeManager sourceDtm = dtmHandler.getDataTypeManager(sourceArchive);
		if (dataTypeManager == null || sourceDtm == null) {
			return false;
		}
		DataType sourceDt = sourceDtm.getDataType(sourceArchive, dt.getUniversalID());
		update(dataTypeManager, sourceDt);
		return true;
	}

	public void markSynchronized() {
		int transactionID = dataTypeManager.startTransaction("Clear Dirty Flag");
		try {
			sourceArchive.setDirtyFlag(false);
			sourceArchive.setLastSyncTime(sourceDTM.getLastChangeTimeForMyManager());
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	public void removeSourceArchive() {
		int transactionID = dataTypeManager.startTransaction("Remove Source Archive");
		try {
			dataTypeManager.removeSourceArchive(sourceArchive);
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	public String getArchiveName() {
		return sourceArchive.getName();
	}

//	public void openTransactions() {
////		if (sourceDTM != null) {
////			sourceTransactionID = sourceDTM.startTransaction("Data Type Synchronization");
////		}
//		localTransactionID = dataTypeManager.startTransaction("Data Type Synchronization");
//	}
//
//	public void closeTransactions() {
//		dataTypeManager.endTransaction(localTransactionID, true);
////		if (sourceDTM != null) {
////			sourceDTM.endTransaction(sourceTransactionID, true);
////		}
//
//	}

	/**
	 * If the indicated data type is associated with a source archive, this will remove the
	 * association.
	 * @param dataType the data type to be disassociated from a source archive.
	 */
	public static void disassociate(DataType dataType) {
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		int transactionID = dataTypeManager.startTransaction("Disassociate Data Type");
		try {
			dataTypeManager.disassociate(dataType);
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	private static void renameDataType(DataTypeManager sourceDTM, DataType sourceDT,
			DataType dtToCopy) {
		if (isAutoNamedTypedef(dtToCopy)) {
			if (sourceDT instanceof TypeDef) {
				((TypeDef) sourceDT).enableAutoNaming();
				return;
			}
		}
		String name = dtToCopy.getName();
		CategoryPath path = sourceDT.getCategoryPath();
		if (sourceDTM.getDataType(path, name) != null) {
			name = ((DataTypeManagerDB) sourceDTM).getUnusedConflictName(sourceDT.getCategoryPath(),
				dtToCopy);
		}
		try {
			sourceDT.setName(name);
		}
		catch (InvalidNameException e) {
			throw new AssertException(
				"This should not occur here, all we did is tack more on the end");
		}
		catch (DuplicateNameException e) {
			throw new AssertException(
				"This should not occur here, we already looked to see if it existed");
		}
	}

	private static boolean isAutoNamedTypedef(DataType dt) {
		if (dt instanceof TypeDef) {
			TypeDef td = (TypeDef) dt;
			return td.isAutoNamed();
		}
		return false;
	}

	static boolean isPointerOrArray(DataType dt) {
		return (dt instanceof Pointer) || (dt instanceof Array);
	}

	static boolean namesAreEquivalent(DataType dt1, DataType dt2) {
		if (isAutoNamedTypedef(dt1)) {
			return isAutoNamedTypedef(dt2);
		}
		else if (isAutoNamedTypedef(dt2)) {
			return false;
		}
		return DataTypeUtilities.getNameWithoutConflict(dt1)
				.equals(DataTypeUtilities.getNameWithoutConflict(dt2));

	}

	public static DataTypeSyncState getSyncStatus(DataTypeManagerHandler handler,
			DataType dataType) {
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		SourceArchive sourceArchive = dataType.getSourceArchive();
		UniversalID dataTypeID = dataType.getUniversalID();
		if (sourceArchive == null || dataTypeID == null ||
			sourceArchive.getSourceArchiveID().equals(dataTypeManager.getUniversalID())) {
			return DataTypeSyncState.UNKNOWN;
		}
		boolean hasChangedLocally =
			dataType.getLastChangeTime() != dataType.getLastChangeTimeInSourceArchive();

		DataTypeManager sourceDTM = handler.getDataTypeManager(sourceArchive);
		DataTypeSyncInfo syncInfo = new DataTypeSyncInfo(dataType, sourceDTM);
		if (sourceDTM == null) {
			return hasChangedLocally ? DataTypeSyncState.COMMIT : DataTypeSyncState.IN_SYNC;
		}
		return syncInfo.getSyncState();
	}

	public static String getDiffToolTip(DataTypeManagerHandler handler, DataType dataType) {
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		SourceArchive sourceArchive = dataType.getSourceArchive();
		UniversalID dataTypeID = dataType.getUniversalID();
		if (sourceArchive == null || dataTypeID == null ||
			sourceArchive.getSourceArchiveID().equals(dataTypeManager.getUniversalID())) {
			return null;
		}

		DataTypeManager sourceDTM = handler.getDataTypeManager(sourceArchive);
		boolean hasChangedLocally =
			dataType.getLastChangeTime() != dataType.getLastChangeTimeInSourceArchive();
		DataType sourceDT = null;
		if (sourceDTM == null) {
			if (!hasChangedLocally) {
				return null;
			}
		}
		else {
			sourceDT = sourceDTM.getDataType(sourceArchive, dataTypeID);
		}
		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(dataType);
		HTMLDataTypeRepresentation representation2 =
			getSourceHTMLRepresentation(sourceDT, sourceArchive);
		HTMLDataTypeRepresentation[] diffs = representation1.diff(representation2);

		String htmlContent = diffs[0].getHTMLContentString();
		String otherContent = diffs[1].getHTMLContentString();

		// this string allows us to force both tables to be the same width, which is
		// aesthetically pleasing
		String spacerString = createHTMLSpacerString(htmlContent, otherContent);
		StringBuilder buffy = new StringBuilder();
		buffy.append("<html>");

		// -we use CELLPADDING here to allow us to create a narrow column within the table
		// -the CELLSPACING gives us some space around the narrow column
		buffy.append("<TABLE BORDER=0 CELLPADDING=0 CELLSPACING=5>");

		buffy.append("<TR BORDER=LEFT>");
		buffy.append("<TD VALIGN=\"TOP\">");
		buffy.append("<B>")
				.append(HTMLUtilities.escapeHTML(dataTypeManager.getName()))
				.append("</B><HR NOSHADE>");
		buffy.append(htmlContent);

		// horizontal spacer below the inner table in order to force a minimum width
		buffy.append("<TT>").append(spacerString).append("</TT>");
		buffy.append("</TD>");

		// really narrow, black column that represents our table divider (like a vertical HR)
		buffy.append("<TD WIDTH=\"1\" BGCOLOR=#000000>");
		buffy.append("</TD>");

		buffy.append("<TD VALIGN=\"TOP\">");
		buffy.append("<B>")
				.append(HTMLUtilities.escapeHTML(sourceArchive.getName()))
				.append("</B><HR NOSHADE>");

		buffy.append(otherContent);

		// horizontal spacer below the inner table in order to force a minimum width
		buffy.append("<TT>").append(spacerString).append("</TT>");
		buffy.append("</TD>");
		buffy.append("</TR>");

		buffy.append("</TABLE>");

		return buffy.toString();
	}

	private static HTMLDataTypeRepresentation getSourceHTMLRepresentation(DataType sourceDT,
			SourceArchive sourceArchive) {
		if (sourceDT == null) {
			return new MissingArchiveDataTypeHTMLRepresentation(sourceArchive);
		}
		return ToolTipUtils.getHTMLRepresentation(sourceDT);
	}

	/**
	 * Compares the two HTML strings to find the widest *rendered* text and then creates
	 * an HTML string of spaces that is wide enough to represent that width.
	 */
	private static String createHTMLSpacerString(String htmlContent, String otherHTMLContent) {
		// unfortunately, to get the displayed widths, we have to have rendered content, which
		// is what the JLabels below are doing for us
		JLabel label1 = new GDHtmlLabel("<html>" + htmlContent);
		JLabel label2 = new GDHtmlLabel("<html>" + otherHTMLContent);

		int maxPixelWidth =
			Math.max(label1.getPreferredSize().width, label2.getPreferredSize().width);
		FontMetrics fontMetrics = label1.getFontMetrics(label1.getFont());
		StringBuilder bigBuffy = new StringBuilder();
		String HTMLSpace = "&nbsp";
		int invisibleCharCount = HTMLSpace.length();
		for (int i = 0; i < 150; i++) {
			bigBuffy.append(HTMLSpace);

			// this is the width of *displayable* characters
			int width = SwingUtilities.computeStringWidth(fontMetrics, bigBuffy.toString());
			int currentPixelWidth = width / invisibleCharCount;
			if (currentPixelWidth >= maxPixelWidth) {
				break;
			}
		}

		return bigBuffy.toString();
	}

	public String getClientName() {
		return dataTypeManager.getName();
	}

	public String getSourceName() {
		if (sourceDTM != null) {
			return sourceDTM.getName();
		}
		return sourceArchive.getName();
	}

	public String getClientType() {
		if (dataTypeManager instanceof ProgramDataTypeManager) {
			return "Program";
		}
//		if (dataTypeManager instanceof ProjectDataTypeManager) {
//			return "Project Archive";
//		}
//		if (dataTypeManager instanceof FileDataTypeManager) {
//			return "File Archive";
//		}
		return "Archive";
	}

	/**
	 * Adjusts the data type and source archive info for an associated source archive if its sync
	 * state is incorrect. It makes sure that a data type that is the same as the associated
	 * archive one is in-sync. It also makes sure that a data type that differs from the archive
	 * one can be committed or updated.
	 */
	public void reSyncDataTypes() {
		if (sourceDTM == null) {
			Msg.info(getClass(),
				"Can't access the data types for the " + sourceArchive.getName() + " archive.");
			return;
		}

		int transactionID =
			dataTypeManager.startTransaction("Sync '" + sourceArchive.getName() + "' data types");
		try {
			reSyncOutOfSyncInTimeOnlyDataTypes();
			fixSyncForDifferingDataTypes();
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	/**
	 * Checks if datatype is really out of sync or is only marked as out of sync but really
	 * is not changed. If datatypes are really in sync, updates the time marks to indicate that
	 * they are in sync;
	 */
	public void reSyncOutOfSyncInTimeOnlyDataTypes() {
		if (sourceDTM == null) {
			Msg.info(getClass(),
				"Can't access the data types for the " + sourceArchive.getName() + " archive.");
			return;
		}

		List<DataTypeSyncInfo> outOfSynchDataTypes = findOutOfSynchDataTypes();
		List<DataTypeSyncInfo> list = new ArrayList<>();

		Iterator<DataTypeSyncInfo> iterator = outOfSynchDataTypes.iterator();
		while (iterator.hasNext()) {
			DataTypeSyncInfo dataTypeSyncInfo = iterator.next();
			if (!dataTypeSyncInfo.hasChange()) {
				list.add(dataTypeSyncInfo);
				iterator.remove();
			}
		}
		autoUpdateDataTypesThatHaveNoRealChanges(list, outOfSynchDataTypes.isEmpty());
	}

	/**
	 * This method is to correct a problem where a data type ends up differing from its associated
	 * data type in the archive, but its timestamp information indicates that it is in sync.
	 * It changes the timestamp info on the data type and the info about the source archive so
	 * the user will be able to commit/update the data type to correctly put it back in sync.
	 */
	private void fixSyncForDifferingDataTypes() {
		boolean fixedSync = false;
		List<DataType> dataTypes = dataTypeManager.getDataTypes(sourceArchive);
		for (DataType dataType : dataTypes) {
			DataTypeSyncInfo dataTypeSyncInfo = new DataTypeSyncInfo(dataType, sourceDTM);
			DataType sourceDataType = dataTypeSyncInfo.getSourceDataType();
			DataTypeSyncState syncState = dataTypeSyncInfo.getSyncState();
			if (syncState == DataTypeSyncState.IN_SYNC && dataTypeSyncInfo.hasChange()) {
				Msg.info(getClass(),
					"Program data type '" + dataType.getPathName() +
						"' differs from its source data type '" + sourceDataType.getPathName() +
						"' and is being changed to not be in-sync!");

				dataType.setLastChangeTimeInSourceArchive(0); // Set timestamp so user must re-sync.
				fixedSync = true;
			}
		}
		if (fixedSync) {
			sourceArchive.setDirtyFlag(true); // Set dirty flag so user must re-sync.
			sourceArchive.setLastSyncTime(0); // Set timestamp so user must re-sync.
		}
	}

	private void autoUpdateDataTypesThatHaveNoRealChanges(
			List<DataTypeSyncInfo> outOfSynchInTimeOnlyList, boolean markArchiveSynchronized) {
		int transactionID = dataTypeManager.startTransaction("Sync datatypes");
		try {
			for (DataTypeSyncInfo dataTypeSyncInfo : outOfSynchInTimeOnlyList) {
				dataTypeSyncInfo.syncTimes();
			}
			if (markArchiveSynchronized) {
				markSynchronized();
			}
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	public void performBulkOperation(String actionName, List<DataTypeSyncInfo> selectedList,
			ExceptionalConsumer<DataTypeSyncInfo, CancelledException> infoApplier,
			Consumer<List<DataTypeSyncInfo>> handleOutOfSync, boolean sourceRequiresTransaction)
			throws CancelledException {
		if (sourceDTM == null) {
			throw new RuntimeException("Source archive required");
		}

		int sourceTransactionId =
			sourceRequiresTransaction ? sourceDTM.startTransaction(actionName) : 0;
		int transactionID = dataTypeManager.startTransaction(actionName);
		try {
			for (DataTypeSyncInfo info : selectedList) {
				infoApplier.accept(info);
			}
			List<DataTypeSyncInfo> outOfSyncList = findOutOfSynchDataTypes();
			handleOutOfSync.accept(outOfSyncList);
			if (outOfSyncList.isEmpty()) {
				markSynchronized();
			}
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
			if (sourceRequiresTransaction) {
				sourceDTM.endTransaction(sourceTransactionId, true);
			}
		}
	}
}
