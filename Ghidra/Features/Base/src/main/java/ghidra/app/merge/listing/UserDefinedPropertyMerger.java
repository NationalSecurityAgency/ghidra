/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.merge.listing;

import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.app.merge.util.MergeUtilities;
import ghidra.program.database.properties.UnsupportedMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * Class for merging user defined property changes. This class can merge non-conflicting
 * user defined property changes that were made to the checked out version. It can determine
 * where there are conflicts between the latest checked in version and my
 * checked out version. It can then manually merge the conflicting user defined properties.
 * Wherever a user defined property conflict is detected, the user will be allowed to choose
 * the property at the address in conflict from the latest, my or original program.
 * <br>Important: This class is intended to be used only for a single program 
 * version merge. It should be constructed, followed by an autoMerge(), and lastly
 * each address with a conflict should have mergeConflicts() called on it.
 */
class UserDefinedPropertyMerger extends AbstractListingMerger {

	final static String USER_DEFINED_PHASE = "User Defined Properties";
	private PropertyMapManager latestPMM;
	private PropertyMapManager myPMM;
	private PropertyMapManager originalPMM;
	private String propertyName; // the current property name being resolved.
	private AddressSetView myDetailSet;
	private String[] propNames; // All property names available in the latest program and my program combined.
	private AddressSet[] conflictSets; // Conflict set for each named property.
	private AddressSet conflictSet;
	private VerticalChoicesPanel conflictPanel;
	private int[] sameOption; // Same option to use for each named property conflict.
	private int propertyIndex = 0;

	/**
	 * Constructs a user defined properties merger.
	 * @param listingMergeMgr the listing merge manager that owns this merger.
	 */
	UserDefinedPropertyMerger(ListingMergeManager listingMergeMgr) {
		super(listingMergeMgr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	@Override
	public void init() {
		super.init();
		latestPMM = latestPgm.getUsrPropertyManager();
		myPMM = myPgm.getUsrPropertyManager();
		originalPMM = originalPgm.getUsrPropertyManager();
		conflictSet = new AddressSet();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictType()
	 */
	public String getConflictType() {
		return "User Defined Property";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#autoMerge(ghidra.util.task.TaskMonitor)
	 */
	public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		initializeAutoMerge("Auto-merging User Defined Properties and determining conflicts.",
			progressMin, progressMax, monitor);

		// Get where each changed user defined props.
		// Check the overlap to see which truly are conflicts.
		AddressSetView latestDetailSet =
			listingMergeMgr.diffOriginalLatest.getTypeDiffs(ProgramDiffFilter.USER_DEFINED_DIFFS,
				listingMergeMgr.latestSet, monitor);
		myDetailSet =
			listingMergeMgr.diffOriginalMy.getTypeDiffs(ProgramDiffFilter.USER_DEFINED_DIFFS,
				listingMergeMgr.mySet, monitor);
		AddressSet tmpAutoSet = new AddressSet();
		AddressSet overlapSet = new AddressSet();
		MergeUtilities.adjustSets(latestDetailSet, myDetailSet, tmpAutoSet, overlapSet);
		// FUTURE : Change USER_DEFINED_DIFFS to be individual addresses rather than code unit ranges.
		AddressSet autoAllSet = limitToStartofCodeUnits(resultPgm, tmpAutoSet);
		// mergeProperties() won't try to merge Unsupported user defined properties.
		listingMergeMgr.mergeMy.mergeProperties(autoAllSet, monitor);

		propNames = getPropertyNames();
		int numProps = propNames.length;
		totalChanges = numProps;
		changeNum = 0;
		conflictSets = new AddressSet[numProps];
		sameOption = new int[numProps];
		for (int i = 0; i < numProps; i++) {
			conflictSets[i] = new AddressSet();
			sameOption[i] = ASK_USER;
		}

		for (int i = 0; i < propNames.length; i++) {
			propertyIndex = i;
			PropertyMap latestMap = latestPMM.getPropertyMap(propNames[i]);
			PropertyMap myMap = myPMM.getPropertyMap(propNames[i]);
			PropertyMap originalMap = originalPMM.getPropertyMap(propNames[i]);
			// Handle case where the class for a Saveable property is missing.
			if ((latestMap instanceof UnsupportedMapDB) || (myMap instanceof UnsupportedMapDB)) {
				String msg =
					"Encountered unsupported property: " + propNames[i] +
						"\nYour Ghidra may be missing the java class for this property." +
						"\n\nAny changes you have made to this property type will be lost" +
						"\nif you check-in your changes.";
				Msg.showError(this, this.listingMergePanel, "User Defined Property Merge Error",
					msg);
				continue; // ignore property that isn't supported.
			}
			if (!samePropertyTypes(latestMap, myMap)) {
				String msg =
					LATEST_TITLE + " and " + MY_TITLE + " program versions not same type for " +
						propNames[i] + " property.";
				Msg.showError(this, this.listingMergePanel, "User Defined Property Merge Error",
					msg);
			}
			AddressIterator latestIter =
				(latestMap != null) ? latestMap.getPropertyIterator(overlapSet) : null;
			AddressIterator myIter = (myMap != null) ? myMap.getPropertyIterator(overlapSet) : null;
			AddressIterator originalIter =
				(originalMap != null) ? originalMap.getPropertyIterator(overlapSet) : null;
			MultiAddressIterator addrIter =
				new MultiAddressIterator(new AddressIterator[] { latestIter, myIter, originalIter });
			while (addrIter.hasNext()) {
				Address addr = addrIter.next();
				Object latestObj = getProperty(latestMap, addr);
				Object myObj = getProperty(myMap, addr);
				Object originalObj = getProperty(originalMap, addr);
				boolean sameLatestMy = same(latestObj, myObj);
				if (sameLatestMy) {
					// My is already like latest, so do nothing.
					continue;
				}
				boolean sameOriginalLatest = same(originalObj, latestObj);
				boolean sameOriginalMy = same(originalObj, myObj);
				if (sameOriginalLatest) {
					// Only My changed so autoMerge.
					merge(propNames[i], addr, KEEP_MY);
				}
				else if (!sameOriginalMy) {
					// Both changed, so conflict.
					conflictSets[i].addRange(addr, addr);
					conflictSet.addRange(addr, addr);
				}
				// Otherwise only latest changed, so do nothing.
			}
			incrementProgress(1);
		}

		updateProgress(100, "Done auto-merging User Defined Properties and determining conflicts.");
	}

	/**
	 * Gets the property, if there is one, from the specified property map for 
	 * the indicated address.
	 * @param map the property map
	 * @param address the address
	 * @return the property at the address or null if there isn't one.
	 */
	private Object getProperty(PropertyMap map, Address address) {
		if (map instanceof VoidPropertyMap) {
			return ((VoidPropertyMap) map).getNextPropertyAddress(address);
		}
		else if (map instanceof ObjectPropertyMap) {
			return ((ObjectPropertyMap) map).getObject(address);
		}
		else if (map instanceof LongPropertyMap) {
			try {
				return new Long(((LongPropertyMap) map).getLong(address));
			}
			catch (NoValueException e) {
				return null;
			}
		}
		else if (map instanceof IntPropertyMap) {
			try {
				return new Integer(((IntPropertyMap) map).getInt(address));
			}
			catch (NoValueException e) {
				return null;
			}
		}
		else if (map instanceof StringPropertyMap) {
			return ((StringPropertyMap) map).getString(address);
		}
		return null;
	}

	/**
	 * Determines if the indicated property maps are for the same type of property.
	 * @param latestMap the first map
	 * @param myMap the second map
	 * @return true if the property type held by the two maps is the same.
	 * Otherwise, return false.
	 */
	private boolean samePropertyTypes(PropertyMap latestMap, PropertyMap myMap) {
		if (latestMap != null && myMap != null) {
			return latestMap.getClass().equals(myMap.getClass());
		}
		return true;
	}

	/**
	 * Determines all of the property names that are available in the latest and my program.
	 * @return the property names.
	 */
	private String[] getPropertyNames() {
		Listing latestListing = latestPgm.getListing();
		Listing myListing = myPgm.getListing();
		Iterator<String> latestProps = latestListing.getUserDefinedProperties();
		Iterator<String> myProps = myListing.getUserDefinedProperties();
		// Combine the 2 property lists into 1 for use with our comparator.
		ArrayList<String> list = new ArrayList<String>();
		while (latestProps.hasNext()) {
			list.add(latestProps.next());
		}
		while (myProps.hasNext()) {
			String propName = myProps.next();
			// Only add the names we don't have yet.
			if (!list.contains(propName) && !propName.equals("Bookmarks")) {
				list.add(propName);
			}
		}
		return list.toArray(new String[list.size()]);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#hasConflict(ghidra.program.model.address.Address)
	 */
	public boolean hasConflict(Address addr) {
		return conflictSet.contains(addr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictCount(ghidra.program.model.address.Address)
	 */
	public int getConflictCount(Address addr) {
		int count = 0;
		for (int i = 0; i < conflictSets.length; i++) {
			AddressSet addrSet = conflictSets[i];
			if (addrSet.contains(addr)) {
				count++;
			}
		}
		return count;
	}

	/**
	 * Creates a conflict panel and adds it to the indicated listing panel.
	 * 
	 * @param listingPanel the merge listing panel
	 * @param propertyName the name of the property in conflict.
	 * @param addr the address where the property is in conflict.
	 * @param changeListener the changeListener that will process the user's selection
	 * when it is made on the conflict panel.
	 */
	private void setupConflictsPanel(ListingMergePanel listingPanel, String propertyName,
			Address addr, ChangeListener changeListener) {
		// Initialize the conflict panel.
		PropertyMap latestPMap = latestPMM.getPropertyMap(propertyName);
		PropertyMap myPMap = myPMM.getPropertyMap(propertyName);
		PropertyMap originalPMap = originalPMM.getPropertyMap(propertyName);
		Object latestObj = null;
		Object myObj = null;
		Object originalObj = null;
		if (latestPMap != null) {
			latestObj = getProperty(latestPMap, addr);
		}
		if (myPMap != null) {
			myObj = getProperty(myPMap, addr);
		}
		if (originalPMap != null) {
			originalObj = getProperty(originalPMap, addr);
		}

		// Get an empty conflict panel.
		if (conflictPanel != null) {
			conflictPanel.clear();
		}
		else {
			conflictPanel = new VerticalChoicesPanel();
			currentConflictPanel = conflictPanel;
		}
		// Add the conflict information to the conflict panel.
		conflictPanel.setConflictType(propertyName + " property");
		conflictPanel.setUseForAll(false);
		conflictPanel.setTitle(getConflictType());

		String latest = createButtonText(LATEST_TITLE, propertyName, latestObj);
		String my = createButtonText(MY_TITLE, propertyName, myObj);
		String original = createButtonText(ORIGINAL_TITLE, propertyName, originalObj);
		String latestStr =
			(latestObj != null) ? ConflictUtility.getTruncatedHTMLString(latestObj.toString(),
				TRUNCATE_LENGTH) : ConflictUtility.NO_VALUE;
		String myStr =
			(myObj != null) ? ConflictUtility.getTruncatedHTMLString(myObj.toString(),
				TRUNCATE_LENGTH) : ConflictUtility.NO_VALUE;
		String originalStr =
			(originalObj != null) ? ConflictUtility.getTruncatedHTMLString(originalObj.toString(),
				TRUNCATE_LENGTH) : ConflictUtility.NO_VALUE;

		conflictPanel.setRowHeader(new String[] { "Option", "'" + propertyName + "' Property" });
		conflictPanel.addRadioButtonRow(new String[] { latest, latestStr }, LATEST_BUTTON_NAME,
			KEEP_LATEST, changeListener);
		conflictPanel.addRadioButtonRow(new String[] { my, myStr }, CHECKED_OUT_BUTTON_NAME,
			KEEP_MY, changeListener);
		conflictPanel.addRadioButtonRow(new String[] { original, originalStr },
			ORIGINAL_BUTTON_NAME, KEEP_ORIGINAL, changeListener);

		listingPanel.setBottomComponent(conflictPanel);
	}

//	public void mergeConflicts(ListingMergePanel listingPanel, int mergeConflictOption, TaskMonitor monitor)
//	throws CancelledException, MemoryAccessException {
//		monitor.setMessage("Resolving "+getConflictType()+" conflicts.");
//		for (int propIndex = 0; propIndex < propNames.length; propIndex++) {
//			propertyIndex = propIndex;
//			sameOption[propIndex] = mergeConflictOption;
//			propertyName = propNames[propIndex];
//			if (conflictPanel != null) {
//				try {
//					SwingUtilities.invokeAndWait(new Runnable() {
//						public void run() {
//							conflictPanel.setPropertyName(propertyName);
//							conflictPanel.setUseForAll(false);
//						}
//					});
//				} catch (InterruptedException e) {
//				} catch (InvocationTargetException e) {
//				}
//			}
//			AddressSet propConflictSet = conflictSets[propIndex];
//			AddressIterator propIter = propConflictSet.getAddresses(true);
//			while (propIter.hasNext()) {
//				Address addr = (Address) propIter.next();
//				if (sameOption[propIndex] == ASK_USER && mergeManager != null) {
//					showMergePanel(listingPanel, propertyName, addr);
//					monitor.checkCanceled();
//				}
//				else {
//					merge(propertyName, addr, sameOption[propIndex]);
//				}
//			}
//		}
//	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#mergeConflicts(ghidra.app.merge.tool.ListingMergePanel, 
	 * ghidra.program.model.address.Address, int, ghidra.util.task.TaskMonitor)
	 */
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr,
			int mergeConflictOption, TaskMonitor monitor) throws CancelledException,
			MemoryAccessException {
		if (!hasConflict(addr)) {
			return;
		}
		monitor.setMessage("Resolving User Defined Property conflicts.");
		for (int i = 0; i < propNames.length; i++) {
			propertyIndex = i;
			propertyName = propNames[i];
			if (conflictSets[i].contains(addr)) {
				if (sameOption[propertyIndex] == ASK_USER && mergeConflictOption != ASK_USER) {
					sameOption[propertyIndex] = mergeConflictOption;
				}
				if (sameOption[propertyIndex] == ASK_USER && mergeManager != null) {
					showMergePanel(listingPanel, propertyName, addr);
					monitor.checkCanceled();
				}
				else {
					merge(propertyName, addr, sameOption[propertyIndex]);
				}
			}
		}
	}

	/**
	 * Merges from the property at the indicated address into the result program 
	 * from the program (latest, my, or original) based on the conflict option.
	 * @param propName the name of the property to merge.
	 * @param addr the address wheree the property is to be merged.
	 * @param mergeConflictOption the conflict option indicating which program 
	 * to merge from. (KEEP_ORIGINAL, KEEP_LATEST, or KEEP_MY)
	 */
	private void merge(String propName, Address addr, int mergeConflictOption) {
		if ((mergeConflictOption & KEEP_ORIGINAL) != 0) {
			listingMergeMgr.mergeOriginal.mergeUserProperty(propName, addr);
		}
		else if ((mergeConflictOption & KEEP_LATEST) != 0) {
			listingMergeMgr.mergeLatest.mergeUserProperty(propName, addr);
		}
		else if ((mergeConflictOption & KEEP_MY) != 0) {
			listingMergeMgr.mergeMy.mergeUserProperty(propName, addr);
		}
	}

	/**
	 * Creates and displays a user defined property conflict to the user.
	 * @param listingPanel the listing merge panel
	 * @param userDefinedPropertyName the name of the property
	 * @param addr the address of the conflict
	 */
	private void showMergePanel(final ListingMergePanel listingPanel,
			final String userDefinedPropertyName, final Address addr) {
		this.propertyName = userDefinedPropertyName;
		this.currentAddress = addr;
		try {
			final ChangeListener changeListener = new ChangeListener() {
				public void stateChanged(ChangeEvent e) {
					conflictOption = conflictPanel.getSelectedOptions();
					if (conflictOption == ASK_USER) {
						if (mergeManager != null) {
							mergeManager.setApplyEnabled(false);
						}
						return;
					}
					if (mergeManager != null) {
						mergeManager.clearStatusText();
					}
					merge(UserDefinedPropertyMerger.this.propertyName,
						UserDefinedPropertyMerger.this.currentAddress, conflictOption);
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
			};
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					setupConflictsPanel(listingPanel, UserDefinedPropertyMerger.this.propertyName,
						UserDefinedPropertyMerger.this.currentAddress, changeListener);
				}
			});
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					listingPanel.clearAllBackgrounds();
					listingPanel.paintAllBackgrounds(new AddressSet(addr, addr));
				}
			});
		}
		catch (InterruptedException e) {
		}
		catch (InvocationTargetException e) {
		}
		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);
			mergeManager.showListingMergePanel(currentAddress);
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
	}

	/**
	 * Creates the text associated with the button for the user's choice.
	 * @param version the program version ("Latest", "Checked Out", "Original")
	 * @param userDefinedPropertyName the name of the property
	 * @param propertyObj the property object.
	 * @return the button's text.
	 */
	private String createButtonText(String version, String userDefinedPropertyName,
			Object propertyObj) {
		if (propertyObj != null) {
			return "Keep '" + version + "' version";
		}
		return "Delete as in '" + version + "' version";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflicts()
	 */
	public AddressSetView getConflicts() {
		return conflictSet;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#apply()
	 */
	@Override
	public boolean apply() {
		numConflictsResolved = 0;
		if (conflictPanel != null) {
			if ((propertyIndex < sameOption.length) && (sameOption[propertyIndex] == ASK_USER) &&
				conflictPanel.getUseForAll()) {
				// "Use same for all" check box got check marked so save the current option selection.
				sameOption[propertyIndex] = conflictOption;
			}
			numConflictsResolved = conflictPanel.getNumConflictsResolved();
			if (conflictPanel.allChoicesAreResolved()) {
				conflictPanel.removeAllListeners();
				return true;
			}
			return false;
		}
		return true;
	}

}
