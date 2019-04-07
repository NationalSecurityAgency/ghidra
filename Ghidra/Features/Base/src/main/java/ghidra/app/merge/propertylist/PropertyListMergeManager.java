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
package ghidra.app.merge.propertylist;

import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.SwingUtilities;

import ghidra.app.merge.MergeResolver;
import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Manages options changes and conflicts between the latest versioned 
 * Program and the Program that is being checked into version control.
 * 
 * 
 */
public class PropertyListMergeManager implements MergeResolver {
	static final int CANCELED = -2; // user canceled the merge operation
	static final int ASK_USER = -1;// prompt the user to choose resolution
	final static int LATEST_VERSION = 1;
	final static int MY_VERSION = 2;
	final static int ORIGINAL_VERSION = 3;

	private static String[] PROPERTY_LIST_PHASE = new String[] { "Property List" };
	private int conflictOption;

	private Program resultProgram;
	private Program myProgram;
	private Program originalProgram;
	private Program latestProgram;
	private TaskMonitor currentMonitor;
	private HashMap<String, ArrayList<ConflictInfo>> conflictMap;
	private PropertyListMergePanel mergePanel;
	private int currentConflict;
	private int totalConflictCount;
	private ProgramMultiUserMergeManager mergeManager;
	private int progressIndex;
	private int propertyListChoice = ASK_USER;

	/**
	 * Construct a new PropertyListMergeManager.
	 * 
	 * @param mergeManager manages each stage of the merge/resolve conflict process
	 * @param resultProgram latest version of the Program that is the 
	 * destination for changes that will be applied from the source program
	 * @param myProgram source of changes to apply to the result
	 * program
	 * @param originalProgram program that was originally checked out
	 * @param latestProgram program that that is the latest version; the
	 * resultProgram and latestProgram start out the same
	 */
	public PropertyListMergeManager(ProgramMultiUserMergeManager mergeManager,
			Program resultProgram, Program myProgram, Program originalProgram, Program latestProgram) {
		this.mergeManager = mergeManager;
		this.resultProgram = resultProgram;
		this.myProgram = myProgram;
		this.originalProgram = originalProgram;
		this.latestProgram = latestProgram;
		conflictMap = new HashMap<String, ArrayList<ConflictInfo>>();
		conflictOption = ASK_USER;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#apply()
	 */
	public void apply() {
		conflictOption = mergePanel.getSelectedOption();

		// If the "Use For All" check box is selected 
		// then save the option chosen for this conflict type.
		if (mergePanel.getUseForAll()) {
			propertyListChoice = conflictOption;
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#cancel()
	 */
	public void cancel() {
		conflictOption = CANCELED;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getDescription()
	 */
	public String getDescription() {
		return "Merge Property Lists";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getName()
	 */
	public String getName() {
		return "Property List Merger";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#merge(ghidra.util.task.TaskMonitor)
	 */
	public void merge(TaskMonitor monitor) {

		mergeManager.setInProgress(PROPERTY_LIST_PHASE);
		this.currentMonitor = monitor;

		currentConflict = 0;
		totalConflictCount = 0;
		List<String> myNames = myProgram.getOptionsNames();
		List<String> latestNames = latestProgram.getOptionsNames();
		List<String> origNames = originalProgram.getOptionsNames();
		int myNamesCount = myNames.size();
		mergeManager.updateProgress(0, "Merging Property Lists...");
		int transactionID = resultProgram.startTransaction("Merge Property Lists");
		boolean commit = false;
		try {
			currentMonitor.initialize(myNamesCount);
			for (int i = 0; i < myNamesCount; i++) {
				if (monitor.isCancelled()) {
					return;
				}
				currentMonitor.setProgress(i);
				String myName = myNames.get(i);
				int progress = (int) (((float) (i / myNamesCount)) * 100);
				mergeManager.updateProgress(progress, "Merging property list for " + myName + "...");
				boolean isInLatest = latestNames.contains(myName);
				boolean isInOrig = origNames.contains(myName);
				if (!isInLatest && !isInOrig) {
					// add the new property list
					addPropertyList(myName);
				}
				else if (isInLatest) {
					// if latest value did not change but source value did
					// change, update resultProgram with source value
					checkValues(myName);
				}
			}
			mergeManager.updateProgress(100);
			currentMonitor.initialize(myNamesCount);
			try {
				processConflicts();
				commit = true;
			}
			catch (CancelledException e) {
				commit = false;
			}
		}
		finally {
			resultProgram.endTransaction(transactionID, commit);
		}
		mergeManager.setCompleted(PROPERTY_LIST_PHASE);
		currentMonitor.initialize(0);
	}

	/**
	 * For Junit testing purposes only.
	 * @param option option for resolving a conflict
	 */
	void setConflictResolution(int option) {
		conflictOption = option;
	}

	/**
	 * Add the property list to the result program.
	 * @param id of property list
	 */
	private void addPropertyList(String listName) {
		Options list = myProgram.getOptions(listName);
		Options resultList = resultProgram.getOptions(listName);
		for (String optionName : list.getOptionNames()) {
			if (currentMonitor.isCancelled()) {
				return;
			}
			addProperty(list, resultList, optionName);
			currentMonitor.setProgress(++progressIndex);
		}

	}

	private void addProperty(Options myList, Options resultList, String propertyName) {
		Object value = myList.getObject(propertyName, null);
		if (value != null) {
			resultList.putObject(propertyName, value);
		}
	}

	/**
	 * Check the property names in the list; if values changed in both
	 * places, then this is a conflict.
	 * @param listName name of the property list
	 */
	private void checkValues(String listName) {
		Options myList = myProgram.getOptions(listName);
		Options resultList = resultProgram.getOptions(listName);
		Options origList = originalProgram.getOptions(listName);

		List<String> myNameList = myList.getOptionNames();
		List<String> resultNameList = resultList.getOptionNames();

		for (int i = 0; i < myNameList.size(); i++) {
			String name = myNameList.get(i);
			if (resultNameList.contains(name)) {
				updateValue(myList, resultList, origList, name);
			}
			else {
				// not in the result
				checkForAddedProperty(myList, resultList, origList, name);
			}
		}
		checkDeletedProperties(resultList, origList, myNameList, resultNameList,
			origList.getOptionNames());
	}

	/**
	 * Delete the properties
	 * @param latestList
	 * @param myNames
	 * @param latestNames
	 * @param origNames
	 */
	private void checkDeletedProperties(Options latestList, Options origList, List<String> myNames,
			List<String> latestNames, List<String> origNames) {

		for (int i = 0; i < latestNames.size(); i++) {
			String propertyName = latestNames.get(i);
			if (!myNames.contains(propertyName) && origNames.contains(propertyName)) {
				try {
					Object latestValue = getValue(latestList, propertyName);
					Object origValue = getValue(origList, propertyName);

					if (latestValue.equals(origValue)) {
						latestList.removeOption(propertyName);
						currentMonitor.setProgress(++progressIndex);
					}
					else {
						String listName = latestList.getName();
						ArrayList<ConflictInfo> mapList = getConflictList(listName);
						mapList.add(new ConflictInfo(listName, propertyName,
							latestList.getType(propertyName), OptionType.NO_TYPE,
							origList.getType(propertyName), latestValue, null, origValue));
						++totalConflictCount;
					}
				}
				catch (IllegalArgumentException e) {
				}
			}
		}
	}

	private void updateValue(Options myList, Options resultList, Options origList,
			String propertyName) {

		Object myValue = getValue(myList, propertyName);
		Object resultValue = getValue(resultList, propertyName);
		Object origValue = getValue(origList, propertyName);

		if (!SystemUtilities.isEqual(resultValue, myValue)) {
			if (propertyName.equals(Program.ANALYZED) && (myValue instanceof Boolean)) {
				// If latest or my version sets "Analyzed" to true, then it should result in true.
				setValue(resultList, propertyName, myList.getType(propertyName), Boolean.TRUE);
				currentMonitor.setProgress(++progressIndex);
				return;
			}
			if (SystemUtilities.isEqual(resultValue, origValue)) {
				setValue(resultList, propertyName, myList.getType(propertyName), myValue);
				currentMonitor.setProgress(++progressIndex);
			}
			else {
				String listName = resultList.getName();
				ArrayList<ConflictInfo> mapList = getConflictList(listName);
				mapList.add(new ConflictInfo(listName, propertyName,
					resultList.getType(propertyName), myList.getType(propertyName),
					origList.getType(propertyName), resultValue, myValue, origValue));
				++totalConflictCount;
			}
		}
	}

	private ArrayList<ConflictInfo> getConflictList(String listName) {
		ArrayList<ConflictInfo> list = conflictMap.get(listName);
		if (list == null) {
			list = new ArrayList<ConflictInfo>();
			conflictMap.put(listName, list);
		}
		return list;
	}

	/**
	 * The property was not in the latest program; if the value changed
	 * from the original, set the value in the result program.
	 * @param myList property list from source program
	 * @param resultList property list from result program
	 * @param origList property list from the original checked out program
	 * @param propertyName name of the property
	 */
	private void checkForAddedProperty(Options myList, Options resultList, Options origList,
			String propertyName) {

		Object myValue = getValue(myList, propertyName);
		Object origValue = getValue(origList, propertyName);

		if (!myValue.equals(origValue)) {
			setValue(resultList, propertyName, myList.getType(propertyName), myValue);
			currentMonitor.setProgress(++progressIndex);
		}

	}

	private void setValue(Options options, String propertyName, OptionType type, Object value) {

		switch (type) {
			case BOOLEAN_TYPE:
				options.setBoolean(propertyName, ((Boolean) value).booleanValue());
				break;

			case DOUBLE_TYPE:
				options.setDouble(propertyName, ((Double) value).doubleValue());
				break;

			case INT_TYPE:
				options.setInt(propertyName, ((Integer) value).intValue());
				break;

			case LONG_TYPE:
				options.setLong(propertyName, ((Long) value).longValue());
				break;

			case STRING_TYPE:
				options.setString(propertyName, (String) value);
				break;
			case DATE_TYPE:
				options.setDate(propertyName, (Date) value);
				break;

			case NO_TYPE:
			default:
		}
	}

	private Object getValue(Options options, String propertyName) {
		OptionType type = options.getType(propertyName);
		switch (type) {
			case BOOLEAN_TYPE:
				return options.getBoolean(propertyName, false) ? Boolean.TRUE : Boolean.FALSE;

			case DOUBLE_TYPE:
				return new Double(options.getDouble(propertyName, 0d));

			case INT_TYPE:
				return new Integer(options.getInt(propertyName, 0));

			case LONG_TYPE:
				return new Long(options.getLong(propertyName, 0L));

			case NO_TYPE:
				return null;

			case STRING_TYPE:
				return options.getString(propertyName, (String) null);

			case DATE_TYPE:
				return options.getDate(propertyName, (Date) null);

			default:
				return null;
		}
	}

	private void processConflicts() throws CancelledException {
		String[] listNames = new String[conflictMap.size()];
		Iterator<String> iter = conflictMap.keySet().iterator();
		int idx = 0;
		while (iter.hasNext()) {
			listNames[idx] = iter.next();
			++idx;
		}
		Arrays.sort(listNames);
		currentMonitor.initialize(totalConflictCount);
		for (int listNameIndex = 0; listNameIndex < listNames.length; listNameIndex++) {
			if (currentMonitor.isCancelled()) {
				return;
			}
//			propertyListChoice = ASK_USER; // Clear any previous "UseForAll" choice for a different property name.
			String currentListName = listNames[listNameIndex];
			ArrayList<ConflictInfo> list = conflictMap.get(currentListName);
			processConflictList(list, listNameIndex, currentListName);
		}
	}

	private void processConflictList(ArrayList<ConflictInfo> conflictList, int listNameIndex,
			String currentListName) throws CancelledException {

		for (int i = 0; i < conflictList.size(); i++) {
			currentMonitor.setProgress(++progressIndex);

			ConflictInfo info = conflictList.get(i);

			++currentConflict;
			if (propertyListChoice != ASK_USER) {
				conflictOption = propertyListChoice;
			}
			else if (mergeManager != null && conflictOption == ASK_USER) {
				showMergePanel(info, currentConflict, totalConflictCount);
				// block until the user resolves the conflict or cancels the 
				// process 
			}

			switch (conflictOption) {
				case LATEST_VERSION:
					break;// no action required

				case MY_VERSION:
				case ORIGINAL_VERSION:
					Options options = resultProgram.getOptions(info.getListName());
					options.removeOption(info.getPropertyName());
					if (conflictOption == MY_VERSION) {
						Object myValue = info.getMyValue();
						if (myValue != null) {
							setValue(options, info.getPropertyName(), info.getMyType(),
								info.getMyValue());
						}
					}
					else {
						Object origValue = info.getOrigValue();
						if (origValue != null) {
							setValue(options, info.getPropertyName(), info.getOrigType(),
								info.getOrigValue());
						}
					}
					break;

				case CANCELED:
					throw new CancelledException();
			}
			conflictOption = ASK_USER;
		}
	}

	private void showMergePanel(final ConflictInfo info, final int conflictIndex,
			final int totalNumConflicts) {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					if (mergePanel == null) {
						mergePanel = new PropertyListMergePanel(mergeManager, totalNumConflicts);
					}
					mergePanel.setConflictInfo(conflictIndex, info);
				}
			});
		}
		catch (InterruptedException e) {
		}
		catch (InvocationTargetException e) {
		}
		mergeManager.setApplyEnabled(false);
		mergeManager.showComponent(mergePanel, "PropertyListMerge", new HelpLocation(
			HelpTopics.REPOSITORY, "PropertyListConflict"));
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	public String[][] getPhases() {
		return new String[][] { PROPERTY_LIST_PHASE };
	}

}
