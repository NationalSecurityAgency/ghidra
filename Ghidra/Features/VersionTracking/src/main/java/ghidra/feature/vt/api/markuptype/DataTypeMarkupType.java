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
package ghidra.feature.vt.api.markuptype;

import java.util.ArrayList;
import java.util.List;

import ghidra.feature.vt.api.impl.MarkupItemImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.stringable.DataTypeStringable;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.ReplaceDataChoices;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

public class DataTypeMarkupType extends VTMarkupType {

//==================================================================================================
// Factory Methods
//==================================================================================================

	public static final VTMarkupType INSTANCE = new DataTypeMarkupType();

	@Override
	public List<VTMarkupItem> createMarkupItems(VTAssociation association) {

		List<VTMarkupItem> list = new ArrayList<>();

		VTSession session = association.getSession();

		Program sourceProgram = session.getSourceProgram();
		Listing sourceListing = sourceProgram.getListing();
		Address sourceAddress = association.getSourceAddress();
		Data sourceData = sourceListing.getDataAt(sourceAddress);

		Program destinationProgram = session.getDestinationProgram();
		Listing destinationListing = destinationProgram.getListing();
		Address destinationAddress = association.getDestinationAddress();
		Data destinationData = destinationListing.getDataAt(destinationAddress);

		if (sourceData == null || destinationData == null) {
			return list; // Quit if there isn't a Data unit at source and destination.
		}

		MarkupItemImpl markupItem = new MarkupItemImpl(association, this, sourceAddress);
		if (destinationAddress != null) {
			markupItem.setDefaultDestinationAddress(destinationAddress,
				VTMarkupItem.DATA_ADDRESS_SOURCE);
		}
		list.add(markupItem);

		return list;
	}

	@Override
	public Address validateDestinationAddress(VTAssociation association, Address sourceAddress,
			Address suggestedDestinationAddress) {
		return association.getDestinationAddress();
	}

//==================================================================================================
// End Factory Methods
//==================================================================================================

	private DataTypeMarkupType() {
		super("Data Type");
	}

	@Override
	public boolean supportsApplyAction(VTMarkupItemApplyActionType applyAction) {
		return applyAction == VTMarkupItemApplyActionType.REPLACE_DEFAULT_ONLY ||
			applyAction == VTMarkupItemApplyActionType.REPLACE_FIRST_ONLY ||
			applyAction == VTMarkupItemApplyActionType.REPLACE;
	}

	@Override
	public boolean supportsAssociationType(VTAssociationType matchType) {
		return matchType == VTAssociationType.DATA;
	}

	private Data getSourceData(VTAssociation association, Address sourceAddress) {
		VTSession session = association.getSession();
		Program sourceProgram = session.getSourceProgram();
		Listing sourceListing = sourceProgram.getListing();
		return sourceListing.getDataAt(sourceAddress);
	}

	private Data getDestinationData(VTAssociation association, Address destinationAddress) {
		VTSession session = association.getSession();
		Program destinationProgram = session.getDestinationProgram();
		Listing destinationListing = destinationProgram.getListing();
		return destinationListing.getDataAt(destinationAddress);
	}

	@Override
	public Stringable getSourceValue(VTAssociation association, Address sourceAddress) {
		VTSession session = association.getSession();
		Program sourceProgram = session.getSourceProgram();
		Listing sourceListing = sourceProgram.getListing();
		Data sourceData = sourceListing.getDataAt(sourceAddress);
		if (sourceData == null) {
			return null;
		}
		DataType dataType = sourceData.getDataType();
		int length = sourceData.getLength();
		DataTypeManager dataTypeManager = sourceProgram.getDataTypeManager();
		return new DataTypeStringable(dataType, dataTypeManager, length);
	}

	@Override
	public Stringable getCurrentDestinationValue(VTAssociation association,
			Address destinationAddress) {
		if (destinationAddress == null || destinationAddress == Address.NO_ADDRESS) {
			return null;
		}
		VTSession session = association.getSession();
		Program destinationProgram = session.getDestinationProgram();
		Listing destinationListing = destinationProgram.getListing();
		Data destinationData = destinationListing.getDataAt(destinationAddress);
		if (destinationData == null) {
			return null;
		}
		DataType dataType = destinationData.getDataType();
		DataTypeManager dataTypeManager = destinationProgram.getDataTypeManager();
		return new DataTypeStringable(dataType, dataTypeManager, destinationData.getLength());
	}

	@Override
	public Stringable getOriginalDestinationValue(VTAssociation association,
			Address destinationAddress) {
		return getCurrentDestinationValue(association, destinationAddress);
	}

	@Override
	public VTMarkupItemApplyActionType getApplyAction(ToolOptions options) {
		VTMatchApplyChoices.ReplaceDataChoices replaceChoice;
		try {
			replaceChoice = options.getEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
				ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
		}
		catch (ClassCastException e) {
			options.removeOption(VTOptionDefines.DATA_MATCH_DATA_TYPE);
			replaceChoice = options.getEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
				ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
		}
		switch (replaceChoice) {
			case REPLACE_FIRST_DATA_ONLY:
			case REPLACE_ALL_DATA:
			case REPLACE_UNDEFINED_DATA_ONLY:
				return VTMarkupItemApplyActionType.REPLACE;
			case EXCLUDE:
			default:
				return null;
		}
	}

	@Override
	public Options convertOptionsToForceApplyOfMarkupItem(VTMarkupItemApplyActionType applyAction,
			ToolOptions applyOptions) {
		ToolOptions options = applyOptions.copy();
		switch (applyAction) {
			case ADD:
				throw new IllegalArgumentException(
					getDisplayName() + " markup items cannot perform a Add action.");
			case ADD_AS_PRIMARY:
				throw new IllegalArgumentException(
					getDisplayName() + " markup items cannot perform an Add As Primary action.");
			case REPLACE_DEFAULT_ONLY:
				options.setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
					ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
				break;
			case REPLACE_FIRST_ONLY:
				options.setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
					ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
				break;
			case REPLACE:
				options.setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
					ReplaceDataChoices.REPLACE_ALL_DATA);
				break;
		}
		return options;
	}

	private boolean setDataType(Program program, Address startAddress, DataType dataType,
			int dataLength, VTMatchApplyChoices.ReplaceDataChoices replaceChoice)
			throws CodeUnitInsertionException, DataTypeConflictException,
			VersionTrackingApplyException {

		Listing listing = program.getListing();
		// For now this will only clear the code unit at the address.
		// If the new Data doesn't fit we should get a CodeUnitInsertionException.
		Data originalData = listing.getDataAt(startAddress);
		if (originalData == null) {
			throw new VersionTrackingApplyException(
				"Data Type Markup cannot be applied since there isn't Data at the destination address!");
		}
		DataType originalDataType = originalData.getDataType();
		int originalDataLength = originalData.getLength();
		Address endAddress;
		try {
			endAddress = startAddress.add(dataLength - 1);
		}
		catch (AddressOutOfBoundsException e) {
			endAddress = null;
		}
		if (endAddress == null || !startAddress.hasSameAddressSpace(endAddress)) {
			throw new VersionTrackingApplyException(
				"Data Type Markup cannot be applied since there isn't enough space at the " +
					"destination address!");
		}
		AddressSet addressSet = new AddressSet(startAddress, endAddress);
		InstructionIterator instructions = listing.getInstructions(addressSet, true);
		boolean hasInstructions = instructions.hasNext();
		if (hasInstructions) {
			String message =
				"Data Type Markup cannot be applied because instructions exist where the data " +
					"type is to be applied. Instructions must be cleared in the destination " +
					"program from " + startAddress.toString() + " to " + endAddress.toString() +
					" before this Data Type Markup can be applied.";
			throw new VersionTrackingApplyException(message);
		}
		boolean replaceUndefinedDataOnly =
			(replaceChoice == ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
		boolean replaceFirstOnly = (replaceChoice == ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);

		DataIterator definedData = listing.getDefinedData(addressSet, true);
		boolean hasDefinedData = definedData.hasNext();
		Data nextNonUndefinedDataAfter =
			DataUtilities.getNextNonUndefinedDataAfter(program, startAddress, endAddress);
		boolean hasOtherDefinedData = nextNonUndefinedDataAfter != null;

		if (replaceUndefinedDataOnly && hasDefinedData) {
			// Just return since we are only replacing undefined data and this has some defined data.
			return false;
		}

		if (replaceFirstOnly && hasOtherDefinedData) {
			// Just return since we are only replacing first data and this has some defined 
			// data that would be overwritten following the first data in the destination.
			return false;
		}

		listing.clearCodeUnits(startAddress, endAddress, false); // Clear the necessary code units.

		try {
			listing.createData(startAddress, dataType, dataLength);
		}
		catch (CodeUnitInsertionException e) {
			tryToRestoreOriginalData(listing, startAddress, originalDataType, originalDataLength);
			throw e;
		}
		catch (DataTypeConflictException e) {
			tryToRestoreOriginalData(listing, startAddress, originalDataType, originalDataLength);
			throw e;
		}
		return true;
	}

	private void tryToRestoreOriginalData(Listing listing, Address address,
			DataType originalDataType, int originalDataLength) {

		try {
			listing.createData(address, originalDataType, originalDataLength);
		}
		catch (CodeUnitInsertionException e2) {
			// If we get an error trying to put the original back then dump a message and bail out.
			Msg.error(this,
				"Couldn't restore data type of " + originalDataType.getName() +
					" after failing to set data type markup at " + address.toString() + ".\n" +
					e2.getMessage());
		}
		catch (DataTypeConflictException e2) {
			// If we get an error trying to put the original back then dump a message and bail out.
			Msg.error(this,
				"Couldn't restore data type of " + originalDataType.getName() +
					" after failing to set data type markup at " + address.toString() + ".\n" +
					e2.getMessage());
		}
	}

	@Override
	public boolean applyMarkup(VTMarkupItem markupItem, ToolOptions markupOptions)
			throws VersionTrackingApplyException {

		VTMatchApplyChoices.ReplaceDataChoices replaceChoice = markupOptions.getEnum(
			VTOptionDefines.DATA_MATCH_DATA_TYPE, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);

		VTAssociation association = markupItem.getAssociation();
		Address sourceAddress = markupItem.getSourceAddress();
		Address destinationAddress = markupItem.getDestinationAddress();

		if (destinationAddress == null) {
			throw new VersionTrackingApplyException("The destination address cannot be null!");
		}

		if (destinationAddress == Address.NO_ADDRESS) {
			throw new VersionTrackingApplyException(
				"The destination address cannot be No Address!");
		}

		Data sourceData = getSourceData(association, sourceAddress);
		Data destinationData = getDestinationData(association, destinationAddress);
		if (sourceData == null) {
			throw new VersionTrackingApplyException("The source Data cannot be null!");
		}
		if (destinationData == null) {
			throw new VersionTrackingApplyException("The destination Data cannot be null!");
		}

		DataType sourceDataType = sourceData.getDataType();
		DataType destinationDataType = destinationData.getDataType();
		if (SystemUtilities.isEqual(sourceDataType, destinationDataType)) {
			return false;
		}
		VTSession session = association.getSession();
		Program destinationProgram = session.getDestinationProgram();

		int sourceDataLength = sourceDataType.getLength();
		if (sourceDataLength <= 0) {
			sourceDataLength = sourceData.getLength();
		}

		try {
			return setDataType(destinationProgram, destinationAddress, sourceDataType,
				sourceDataLength, replaceChoice);
		}
		catch (CodeUnitInsertionException e) {

			throw new VersionTrackingApplyException(getApplyFailedMessage(sourceAddress,
				destinationAddress, e, sourceDataLength, destinationData.getLength()), e);
		}
		catch (DataTypeConflictException e) {
			throw new VersionTrackingApplyException(getApplyFailedMessage(sourceAddress,
				destinationAddress, e, sourceDataLength, destinationData.getLength()), e);
		}
	}

	private String getApplyFailedMessage(Address sourceAddress, Address destinationAddress,
			Exception e, int newLength, int oldLength) {
		Address startAddress = destinationAddress.add(oldLength);
		Address endAddress = destinationAddress.add(newLength - 1);
		String message =
			"Couldn't apply Data Type Markup from source address " + sourceAddress.toString() +
				" to destination address " + destinationAddress.toString() + e.getMessage() + ".";
		if (newLength > oldLength) {
			message += " Any Defined Data must be cleared in the destination program from " +
				startAddress.toString() + " to " + endAddress.toString() +
				" before this Data Type Markup can be applied.";
		}
		return message;
	}

	@Override
	public void unapplyMarkup(VTMarkupItem markupItem) throws VersionTrackingApplyException {
		VTMarkupItemStatus status = markupItem.getStatus();
		if (status == VTMarkupItemStatus.DONT_CARE) {
			return; // nothing to do, as we did not change our state in the first place
		}

		Address destinationAddress = markupItem.getDestinationAddress();
		Program destinationProgram = getDestinationProgram(markupItem.getAssociation());
		DataTypeManager destinationDTM = destinationProgram.getDataTypeManager();
		DataTypeStringable dataTypeStringable =
			(DataTypeStringable) markupItem.getOriginalDestinationValue();
		long originalDataTypeID = dataTypeStringable.getDataTypeID();
		long savedUniversalID = dataTypeStringable.getDataTypeManagerID();
		long actualUniversalID = destinationDTM.getUniversalID().getValue();
		if (actualUniversalID != savedUniversalID) {
			throw new AssertException("Destination data type manager ID of " + actualUniversalID +
				" doesn't match saved ID of " + savedUniversalID + ".");
		}

		DataType originalDataType = destinationDTM.getDataType(originalDataTypeID);
		int originalDataLength = originalDataType.getLength();
		if (originalDataLength <= 0) {
			originalDataLength = dataTypeStringable.getLength();
		}

		try {
			setDataType(destinationProgram, destinationAddress, originalDataType,
				originalDataLength, VTMatchApplyChoices.ReplaceDataChoices.REPLACE_ALL_DATA);
		}
		catch (CodeUnitInsertionException e) {
			throw new VersionTrackingApplyException("Couldn't unapply data type markup @ " +
				destinationAddress.toString() + "." + e.getMessage() + ".", e);
		}
		catch (DataTypeConflictException e) {
			throw new VersionTrackingApplyException("Couldn't unapply data type markup @ " +
				destinationAddress.toString() + "." + e.getMessage() + ".", e);
		}
	}

	@Override
	public ProgramLocation getDestinationLocation(VTAssociation association,
			Address destinationAddress) {
		return getListingDataTypeLocation(association, destinationAddress, false);
	}

	@Override
	public ProgramLocation getSourceLocation(VTAssociation association, Address sourceAddress) {
		return getListingDataTypeLocation(association, sourceAddress, true);
	}

	private ProgramLocation getListingDataTypeLocation(VTAssociation association, Address address,
			boolean isSource) {

		if (address == null || address == Address.NO_ADDRESS) {
			return null; // Return null when there is no address.
		}

		Program program;
		if (isSource) {
			program = getSourceProgram(association);
		}
		else {
			program = getDestinationProgram(association);
		}

		Data data = program.getListing().getDataContaining(address);
		if (data == null) {
			// Otherwise, get the address location.
			return new AddressFieldLocation(program, address);
		}

		Stringable value = isSource ? getSourceValue(association, address)
				: getCurrentDestinationValue(association, address);
		String displayString = (value != null) ? value.getDisplayString() : null;
		return new MnemonicFieldLocation(program, address, null, null, displayString, 0);
	}

	@Override
	public boolean hasSameSourceAndDestinationValues(VTMarkupItem markupItem) {
		VTAssociation association = markupItem.getAssociation();
		Address sourceAddress = markupItem.getSourceAddress();
		Address destinationAddress = markupItem.getDestinationAddress();
		// Show data types that don't yet have a destination.
		if (destinationAddress == null || destinationAddress == Address.NO_ADDRESS) {
			return false;
		}
		Data sourceData = getSourceData(association, sourceAddress);
		Data destinationData = getDestinationData(association, destinationAddress);
		if (sourceData == null) {
			return true;
		}
		if (destinationData == null) {
			return false;
		}
		int sourceLength = sourceData.getLength();
		int destinationLength = destinationData.getLength();
		if (sourceLength != destinationLength) {
			return false;
		}
		DataType sourceDataType = sourceData.getDataType();
		DataType destinationDataType = destinationData.getDataType();
		// Don't show data types that are equivalent.
		return sourceDataType.isEquivalent(destinationDataType);
	}
}
