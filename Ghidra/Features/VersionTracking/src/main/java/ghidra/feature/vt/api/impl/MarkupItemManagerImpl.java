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
package ghidra.feature.vt.api.impl;

import ghidra.feature.vt.api.db.*;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTMarkupItemStatus;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import java.util.*;

public class MarkupItemManagerImpl {

	private static final List<VTMarkupItem> EMPTY_LIST =
		Collections.unmodifiableList(new ArrayList<VTMarkupItem>());

	// Local markup item cache.  We depend upon caching of the associations in the manager to
	// keep memory usage from getting out-of-control
	private List<VTMarkupItem> markupItems = EMPTY_LIST;
	private boolean isCreatingMarkupItems;

	private final VTAssociationDB association;

	public MarkupItemManagerImpl(VTAssociationDB association) {
		this.association = association;
	}

	public boolean hasAppliedMarkupItems() {
		if (markupItems == EMPTY_LIST) {
			return hasAppliedStoredMarkupItems();
		}

		for (VTMarkupItem markupItem : markupItems) {
			if (markupItem.canUnapply()) {
				return true;
			}
		}

		return false;
	}

	// this may be called from threaded tables and from swing...make sure we don't lazy load the
	// data more than once
	public synchronized List<VTMarkupItem> getMarkupItems(TaskMonitor monitor)
			throws CancelledException {
		if (isCreatingMarkupItems) {
			return EMPTY_LIST;
		}

		if (markupItems == EMPTY_LIST) {
			isCreatingMarkupItems = true;
			markupItems = createMarkupItems(monitor);
			isCreatingMarkupItems = false;
		}
		return Collections.unmodifiableList(markupItems);
	}

	protected List<VTMarkupItem> createMarkupItems(TaskMonitor monitor) throws CancelledException {

		Collection<VTMarkupItem> generatedMarkupItems = getGeneratedMarkupItems(monitor);
		Collection<VTMarkupItem> databaseMarkupItems = getStoredMarkupItems(monitor);
		return replaceGeneratedMarkupItemsWithDBMarkupItems(generatedMarkupItems,
			databaseMarkupItems);
	}

	protected Collection<VTMarkupItem> getGeneratedMarkupItems(TaskMonitor monitor)
			throws CancelledException {
		return MarkupItemFactory.generateMarkupItems(monitor, association);
	}

	private boolean hasAppliedStoredMarkupItems() {
		AssociationDatabaseManager associationDBM = association.getAssociationManagerDB();
		try {
			// Assumption!: we are passing a dummy monitor under the assumption that this lookup
			//              will be speedy. If this is found to be false, then we need to take a
			//              monitor into this method.
			Collection<MarkupItemStorageDB> databaseMarkupItems =
				associationDBM.getAppliedMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR, association);
			for (MarkupItemStorageDB appliedItem : databaseMarkupItems) {
				VTMarkupItemStatus status = appliedItem.getStatus();
				if (status.isUnappliable()) {
					return true;
				}
			}
		}
		catch (CancelledException e) {
			// cannot happen as long as we are using a dummy monitor
		}
		return false;
	}

	private Collection<VTMarkupItem> getStoredMarkupItems(TaskMonitor monitor)
			throws CancelledException {
		AssociationDatabaseManager associationDBM = association.getAssociationManagerDB();
		Collection<MarkupItemStorageDB> appliedMarkupItems =
			associationDBM.getAppliedMarkupItems(monitor, association);
		List<VTMarkupItem> list = new ArrayList<VTMarkupItem>();
		for (MarkupItemStorageDB markupItemStorageDB : appliedMarkupItems) {
			list.add(new MarkupItemImpl(markupItemStorageDB));
		}
		return list;
	}

	private List<VTMarkupItem> replaceGeneratedMarkupItemsWithDBMarkupItems(
			Collection<VTMarkupItem> generatedMarkupItems,
			Collection<VTMarkupItem> databaseMarkupItems) {

		//
		// We will put all of the generated items in the map first, followed by those in the
		// database.  This will cause the database items to overwrite the generated entries in
		// the map (we always prefer DB versions over the generated).
		// 
		Map<String, VTMarkupItem> map = new HashMap<String, VTMarkupItem>();
		for (VTMarkupItem markupItem : generatedMarkupItems) {
			map.put(getMarkupItemMapKey(markupItem), markupItem);
		}

		for (VTMarkupItem markupItem : databaseMarkupItems) {
			map.put(getMarkupItemMapKey(markupItem), markupItem);
		}

		return new ArrayList<VTMarkupItem>(map.values());
	}

	private String getMarkupItemMapKey(VTMarkupItem markupItem) {
		return markupItem.getMarkupType().getDisplayName() +
			markupItem.getSourceAddress().toString(true);
	}

	public void clearCache() {
		markupItems = EMPTY_LIST;
	}

}
