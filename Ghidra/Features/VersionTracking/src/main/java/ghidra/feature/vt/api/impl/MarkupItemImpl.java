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
package ghidra.feature.vt.api.impl;

import static ghidra.feature.vt.api.main.VTMarkupItemDestinationAddressEditStatus.*;
import static ghidra.feature.vt.api.main.VTMarkupItemStatus.*;
import ghidra.feature.vt.api.db.VTAssociationDB;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.*;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

import java.util.Collection;

public class MarkupItemImpl implements VTMarkupItem {
	private VTMarkupType markupType;
	private MarkupItemStorage markupItemStorage;
	private Stringable cachedSourceValue;
	private Stringable cachedDestinationValue;
	private Stringable cachedOriginalDestinationValue;
	private long sourceModificationNumber;
	private long destinationModificationNumber;
	private Boolean hasSameValues;
	private static boolean isUnApplyingItems = false;
	private static boolean gettingStatus = false;

	public MarkupItemImpl(VTAssociation association, VTMarkupType markupType, Address sourceAddress) {
		this(new MarkupItemStorageImpl(association, markupType, sourceAddress));
	}

	public MarkupItemImpl(MarkupItemStorage markupItem) {
		this.markupItemStorage = markupItem;
		markupType = markupItem.getMarkupType();
	}

	@Override
	public void setDefaultDestinationAddress(Address address, String addressSource) {
		doSetDestinationAddress(address, addressSource, true);
	}

	@Override
	public void setDestinationAddress(Address destinationAddress) {
		doSetDestinationAddress(destinationAddress, USER_DEFINED_ADDRESS_SOURCE, false);
	}

	private void doSetDestinationAddress(Address address, String addressSource, boolean isDefault) {
		if (canUnapply()) {
			throw new IllegalStateException("Can't set destination address on applied markup item");
		}

		// make sure we handle null addresses in a meaningful way--treat them like a reset
		if (address == null) {
			addressSource = null;
		}

		// clear cache
		cachedDestinationValue = null;
		cachedOriginalDestinationValue = null;

		Address oldDestinationAddress = markupItemStorage.getDestinationAddress();
		String oldAddressSource = markupItemStorage.getDestinationAddressSource();
		boolean isResettingAddress =
			USER_DEFINED_ADDRESS_SOURCE.equals(oldAddressSource) &&
				!USER_DEFINED_ADDRESS_SOURCE.equals(addressSource);

		// The following validation call will change the destination address back to an
		// appropriate address if necessary.
		// (For example, function name markup must be on the entry point address.)
		address =
			markupType.validateDestinationAddress(markupItemStorage.getAssociation(),
				markupItemStorage.getSourceAddress(), address);
		if (SystemUtilities.isEqual(address, oldDestinationAddress)) {
			return; // Either the address wasn't changed or we won't let you change this markup address.
		}

		markupItemStorage = markupItemStorage.setDestinationAddress(address, addressSource);

		// Check to set if we have restored the address to a default value and if so, remove
		// our storage from the DB
		markupItemStorage = maybeReset();
		hasSameValues = null;

		if (isDefault && !isResettingAddress) {
			// don't call the setObjectChanged() method, as this address is transient and 
			// we don't want to make the DB dirty
			return;
		}

		VTAssociation association = markupItemStorage.getAssociation();
		VTSessionDB session = (VTSessionDB) association.getSession();
		session.setObjectChanged(VTChangeManager.DOCR_VT_MARKUP_ITEM_DESTINATION_CHANGED, this,
			oldDestinationAddress, address);
	}

	@Override
	public VTMarkupType getMarkupType() {
		return markupItemStorage.getMarkupType();
	}

	@Override
	public VTMarkupItemStatus getStatus() {
		validateDestinationCache();
		VTMarkupItemStatus status = markupItemStorage.getStatus();
		if (status == UNAPPLIED) {
			if (!gettingStatus) {
				try {
					gettingStatus = true;
					boolean conflictsWithOtherMarkup =
						getMarkupType().conflictsWithOtherMarkup(this,
							getAssociation().getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR));
					if (conflictsWithOtherMarkup) {
						return CONFLICT;
					}
				}
				catch (CancelledException e) {
					// Shouldn't happen, but ignore if it does.
				}
				finally {
					gettingStatus = false;
				}
			}
			if (hasSameSourceDestinationValues()) {
				return SAME;
			}
		}
		return status;
	}

	private boolean hasSameSourceDestinationValues() {
		if (hasSameValues == null) {
			hasSameValues = getMarkupType().hasSameSourceAndDestinationValues(this);
		}
		return hasSameValues.booleanValue();
	}

	@Override
	public void setConsidered(VTMarkupItemConsideredStatus consideredStatus) {
		if (canUnapply()) {
			throw new IllegalArgumentException("Cannot set an applied item to considered.");
		}

		VTMarkupItemStatus oldStatus = markupItemStorage.getStatus();
		markupItemStorage = markupItemStorage.setStatus(consideredStatus.getMarkupItemStatus());

		markupItemStorage = maybeReset();

		VTMarkupItemStatus newStatus = markupItemStorage.getStatus();
		if (oldStatus != newStatus) {
			fireMarkupItemStatusChanged(oldStatus, newStatus);
		}
	}

	@Override
	public void apply(VTMarkupItemApplyActionType applyType, ToolOptions options)
			throws VersionTrackingApplyException {

		if (applyType == null) {
			throw new IllegalArgumentException("Apply action type cannot be null!");
		}

		if (getAssociation().getStatus() != VTAssociationStatus.ACCEPTED) {
			throw new VersionTrackingApplyException(
				"Can't apply a markup item for a match that is not accepted.");
		}

		if (options == null) {
			// prevent NPEs
			options = new ToolOptions("VT Options Default");
		}

		VTMarkupItemStatus oldStatus = markupItemStorage.getStatus();
		VTMarkupItemStatus newStatus = oldStatus;

		if (getDestinationAddress() == null) {
			markupItemStorage =
				markupItemStorage.setApplyFailed("Can't apply without a valid destination");
			fireMarkupItemStatusChanged(oldStatus, FAILED_APPLY);
			throw new VersionTrackingApplyException("Cannot apply a markup item without first "
				+ "setting the destination address");
		}

		if (!canApply()) {
			// TODO Should this throw an Exception instead?
//			VTMarkupType itemMarkupType = item.getMarkupType();
//			throw new VersionTrackingApplyException("Cannot apply " +
//				itemMarkupType.getDisplayName() + " at " + item.getDestinationAddress().toString() +
//				".");
			return;
		}

		VTAssociation association = markupItemStorage.getAssociation();
		Stringable sourceValue = markupType.getSourceValue(association, getSourceAddress());
		Stringable destinationValue =
			markupType.getOriginalDestinationValue(association, getDestinationAddress());
		markupItemStorage.setSourceDestinationValues(sourceValue, destinationValue);

		try {

			//
			// TODO: SCR 10062 - We used to use the apply action to do the apply.  Now
			//                   everything is options-based.  Why do we even need the
			//                   'VTMarkupItemApplyActionType'? (bad name, BTW).  At issue
			//                   is the fact that the apply type may be overridden by the
			//                   options.  
			//       
			//                   The state of things right now, with a mix of 'apply type'
			//                   and options, makes the API confusing to me, and probably
			//                   to the user too.
			//

			if (markupType.applyMarkup(this, options)) {
				newStatus = applyType.getApplyStatus();
				markupItemStorage = markupItemStorage.setStatus(newStatus);
			}
		}
		catch (VersionTrackingApplyException e) {
			newStatus = FAILED_APPLY;
			markupItemStorage = markupItemStorage.setApplyFailed(e.getMessage());
			throw e;
		}
		finally {
			if (oldStatus != newStatus) {
				fireMarkupItemStatusChanged(oldStatus, newStatus);
			}
		}
	}

	@Override
	public boolean supportsApplyAction(VTMarkupItemApplyActionType actionType) {
		return markupType.supportsApplyAction(actionType);
	}

	@Override
	public VTAssociation getAssociation() {
		return markupItemStorage.getAssociation();
	}

	@Override
	public ProgramLocation getSourceLocation() {
		return markupType.getSourceLocation(markupItemStorage.getAssociation(),
			markupItemStorage.getSourceAddress());
	}

	@Override
	public ProgramLocation getDestinationLocation() {
		return markupType.getDestinationLocation(markupItemStorage.getAssociation(),
			markupItemStorage.getDestinationAddress());
	}

	public String getDisplayName() {
		return markupType.getDisplayName();
	}

	@Override
	public String getStatusDescription() {
		return markupItemStorage.getStatusDescription();
	}

	@Override
	public String toString() {
		return markupItemStorage.toString();
	}

	@Override
	public VTMarkupItemDestinationAddressEditStatus getDestinationAddressEditStatus() {
		VTMarkupType type = getMarkupType();
		if (type instanceof FunctionEntryPointBasedAbstractMarkupType) {
			return UNEDITABLE_FUNCTION_ENTRY_POINT;
		}
		else if (type instanceof DataTypeMarkupType) {
			return UNEDITABLE_DATA_ADDRESS;
		}

		if (!getAssociation().getStatus().canApply()) {
			return UNEDITABLE_UNAPPLIABLE_ASSOCIATION_STATUS;
		}

		VTMarkupItemStatus status = getStatus();
		if (!status.isAppliable() && status != SAME) {
			return UNEDITABLE_UNAPPLIABLE_MARKUP_STATUS;
		}
		return EDITABLE;
	}

	@Override
	public boolean canApply() {
		VTAssociation association = getAssociation();
		VTAssociationStatus associationStatus = association.getStatus();
		try {
			Collection<VTMarkupItem> markupItems =
				association.getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
			return associationStatus.canApply() && getStatus().isAppliable() &&
				!markupType.conflictsWithOtherMarkup(this, markupItems);
		}
		catch (CancelledException e) {
			return false;
		}
	}

	@Override
	public boolean canUnapply() {
		return markupItemStorage.getStatus().isUnappliable();
	}

	@Override
	public void unapply() throws VersionTrackingApplyException {
		Address destinationAddress = markupItemStorage.getDestinationAddress(); // Save destination address before reset.
		VTMarkupItemStatus oldStatus = markupItemStorage.getStatus();
		markupType.unapplyMarkup(this);
		markupItemStorage.setStatus(UNAPPLIED);

		markupItemStorage = maybeReset();

		VTMarkupItemStatus newStatus = markupItemStorage.getStatus();
		if (oldStatus != newStatus) {
			// the only way these to stati are the same is if you unapply an unapplied
			fireMarkupItemStatusChanged(oldStatus, newStatus);
		}

		// isUnapplyingItems makes sure only the first markup item will try
		// to remove all other items of this type and address.
		if (isUnApplyingItems) {
			return;
		}

		// Unapply other items of this markup type at the same address as this.
		try {
			isUnApplyingItems = true;

			// Reset each markup item that is the same markup type and destination address.
			VTAssociation association = markupItemStorage.getAssociation();
			Collection<VTMarkupItem> markupItems;
			try {
				markupItems = association.getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
				for (VTMarkupItem currentMarkupItem : markupItems) {
					if (currentMarkupItem == this) {
						continue;
					}
					if ((currentMarkupItem.getMarkupType() == markupType) &&
						currentMarkupItem.canUnapply()) {
						Address itemDestination = currentMarkupItem.getDestinationAddress();
						if (destinationAddress.equals(itemDestination)) {
							currentMarkupItem.unapply();
						}
					}
				}
			}
			catch (CancelledException e) {
				// can't happen--dummy monitor
			}
		}
		finally {
			isUnApplyingItems = false;
		}
		hasSameValues = null;
	}

	private MarkupItemStorage maybeReset() {
		//
		// We can reset if the data in the DB is all default data.  The data we care about is 
		// that which can trigger a DB entry to be created, which as of this writing is:
		// 	1) applying
		// 	2) setting an item considered
		//  3) setting a user-defined address
		//
		VTMarkupItemStatus status = getStatus();
		if (!status.isDefault()) {
			return markupItemStorage; // user-defined status or an applied status (cases 1 and 2)
		}

		String addressSource = getDestinationAddressSource();
		if (VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE.equals(addressSource)) {
			return markupItemStorage; // user-defined address value--do not reset (case 3)
		}

		// no user-defined data in the DB--reset!
		hasSameValues = null;
		return markupItemStorage.reset();
	}

	@Override
	public String getDestinationAddressSource() {
		return markupItemStorage.getDestinationAddressSource();
	}

	public boolean isStoredInDB() {
		return (markupItemStorage instanceof DatabaseObject);
	}

	@Override
	public Stringable getCurrentDestinationValue() {
		validateDestinationCache();
		if (cachedDestinationValue == null) {
			cachedDestinationValue =
				markupType.getCurrentDestinationValue(markupItemStorage.getAssociation(),
					markupItemStorage.getDestinationAddress());
		}
		return cachedDestinationValue;
	}

	@Override
	public Stringable getOriginalDestinationValue() {
		Stringable destinationValue = markupItemStorage.getDestinationValue();
		if (destinationValue != null) {
			return destinationValue;
		}
		validateDestinationCache();
		if (cachedOriginalDestinationValue == null) {
			cachedOriginalDestinationValue =
				markupType.getOriginalDestinationValue(markupItemStorage.getAssociation(),
					markupItemStorage.getDestinationAddress());
		}
		return cachedOriginalDestinationValue;
	}

	@Override
	public Stringable getSourceValue() {
		Stringable sourceValue = markupItemStorage.getSourceValue();
		if (sourceValue != null) {
			return sourceValue;
		}
		validateSourceCache();
		if (cachedSourceValue == null) {
			cachedSourceValue =
				markupType.getSourceValue(markupItemStorage.getAssociation(),
					markupItemStorage.getSourceAddress());
		}
		return cachedSourceValue;
	}

	private void validateSourceCache() {
		long currentSourceModificationNumber = getSourceModificationNumber();
		if (sourceModificationNumber != currentSourceModificationNumber) {
			cachedSourceValue = null;
			sourceModificationNumber = currentSourceModificationNumber;
			hasSameValues = null;
		}
	}

	private void validateDestinationCache() {
		long currentDestinationModificationNumber = getDestinationModificationNumber();
		if (destinationModificationNumber != currentDestinationModificationNumber) {
			cachedDestinationValue = null;
			cachedOriginalDestinationValue = null;
			destinationModificationNumber = currentDestinationModificationNumber;
			hasSameValues = null;
		}
	}

	private long getSourceModificationNumber() {
		return markupItemStorage.getAssociation().getSession().getSourceProgram().getModificationNumber();
	}

	private long getDestinationModificationNumber() {
		return markupItemStorage.getAssociation().getSession().getDestinationProgram().getModificationNumber();
	}

	@Override
	public Address getDestinationAddress() {
		return markupItemStorage.getDestinationAddress();
	}

	@Override
	public Address getSourceAddress() {
		return markupItemStorage.getSourceAddress();
	}

	private void fireMarkupItemStatusChanged(VTMarkupItemStatus oldStatus,
			VTMarkupItemStatus newStatus) {

		VTAssociation association = markupItemStorage.getAssociation();
		if (!(association instanceof VTAssociationDB)) {
			return;
		}
		VTAssociationDB associationDB = (VTAssociationDB) association;
		associationDB.markupItemStatusChanged(this);
		VTSessionDB session = (VTSessionDB) association.getSession();
		session.setObjectChanged(VTChangeManager.DOCR_VT_MARKUP_ITEM_STATUS_CHANGED,
			markupItemStorage, oldStatus, newStatus);
	}

}
