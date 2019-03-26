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

import org.apache.commons.lang3.StringUtils;

import ghidra.feature.vt.api.impl.MarkupItemImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.stringable.StringStringable;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.CommentChoices;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.StringUtilities;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public abstract class CommentMarkupType extends VTMarkupType {

	protected abstract int getCodeUnitCommentType();

	public CommentMarkupType(String name) {
		super(name);
	}

	protected abstract ProgramLocation getLocation(VTAssociation association, Address address,
			boolean isSource);

	@Override
	public ProgramLocation getDestinationLocation(VTAssociation association,
			Address destinationAddress) {
		return getLocation(association, destinationAddress, false);
	}

	@Override
	public ProgramLocation getSourceLocation(VTAssociation association, Address sourceAddress) {
		return getLocation(association, sourceAddress, true);
	}

	@Override
	public List<VTMarkupItem> createMarkupItems(VTAssociation association) {
		List<VTMarkupItem> list = new ArrayList<>();

		VTSession session = association.getSession();
		Program sourceProgram = session.getSourceProgram();
		Listing sourceListing = sourceProgram.getListing();
		Address sourceAddress = association.getSourceAddress();
		FunctionManager functionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = functionManager.getFunctionAt(sourceAddress);
		AddressSetView addressSet;
		if (sourceFunction == null) {
			CodeUnit codeUnit = sourceListing.getCodeUnitAt(sourceAddress);
			Address minAddress = codeUnit == null ? sourceAddress : codeUnit.getMinAddress();
			Address maxAddress = codeUnit == null ? sourceAddress : codeUnit.getMaxAddress();
			addressSet = new AddressSet(minAddress, maxAddress);
		}
		else {
			addressSet = sourceFunction.getBody();
		}
		AddressIterator commentAddressIterator =
			sourceListing.getCommentAddressIterator(getCodeUnitCommentType(), addressSet, true);
		while (commentAddressIterator.hasNext()) {
			Address address = commentAddressIterator.next();
			addCommentMarkup(list, address, association, sourceListing);
		}
		return list;
	}

	protected void addCommentMarkup(List<VTMarkupItem> list, Address commentAddress,
			VTAssociation association, Listing sourceListing) {

		// Ignore any empty comments.
		String sourceComment = sourceListing.getComment(getCodeUnitCommentType(), commentAddress);
		boolean hasSourceComment = (sourceComment != null) && (sourceComment.length() > 0);
		if (!hasSourceComment) {
			return; // nothing to apply
		}
		list.add(new MarkupItemImpl(association, this, commentAddress));
	}

	@Override
	public boolean supportsAssociationType(VTAssociationType matchType) {
		return true;
	}

	private String getSourceComment(VTAssociation association, Address sourceAddress) {
		int commentType = getCodeUnitCommentType();
		Listing sourceListing = getSourceListing(association);
		return sourceListing.getComment(commentType, sourceAddress);
	}

	@Override
	public Stringable getSourceValue(VTAssociation association, Address sourceAddress) {
		return new StringStringable(getSourceComment(association, sourceAddress));
	}

	@Override
	public void unapplyMarkup(VTMarkupItem markupItem) throws VersionTrackingApplyException {
		VTMarkupItemStatus status = markupItem.getStatus();
		if (status == VTMarkupItemStatus.DONT_CARE) {
			return; // nothing to do, as we did not change our state in the first place
		}

		Address destinationAddress = markupItem.getDestinationAddress();
		StringStringable originalDestinationValue =
			(StringStringable) markupItem.getOriginalDestinationValue();
		StringStringable currentDestinationValue =
			(StringStringable) markupItem.getCurrentDestinationValue();
		if (currentDestinationValue == null) {
			throw new VersionTrackingApplyException("No value applied");
		}
		String originalDestinationComment = originalDestinationValue.getString();
		int commentType = getCodeUnitCommentType();
		Listing destinationListing = getDestinationListing(markupItem.getAssociation());
		String comment = destinationListing.getComment(commentType, destinationAddress);
		if (!StringUtils.equals(originalDestinationComment, comment)) {
			destinationListing.setComment(destinationAddress, commentType,
				originalDestinationComment);
		}
	}

	public abstract VTMatchApplyChoices.CommentChoices getCommentChoice(ToolOptions options);

	@Override
	public boolean applyMarkup(VTMarkupItem markupItem, ToolOptions markupOptions)
			throws VersionTrackingApplyException {

		Address destinationAddress = markupItem.getDestinationAddress();
		CommentChoices commentChoice = getCommentChoice(markupOptions);

		if (commentChoice == CommentChoices.EXCLUDE) {
			return false;
		}
		if (destinationAddress == null) {
			throw new VersionTrackingApplyException("The destination address cannot be null!");
		}

		if (destinationAddress == Address.NO_ADDRESS) {
			throw new VersionTrackingApplyException(
				"The destination address cannot be No Address!");
		}

		Stringable sourceValue = markupItem.getSourceValue();
		if (sourceValue == null) {
			// someone must have deleted the comment from the source
			throw new VersionTrackingApplyException("Cannot apply comment" +
				".  The data from the source program no longer exists. Markup Item: " + markupItem);
		}

		String sourceComment = ((StringStringable) sourceValue).getString();
		String comment = sourceComment; // Overwrite (replace) destination comment.

		if (commentChoice == CommentChoices.APPEND_TO_EXISTING) {
			StringStringable destinationValue =
				(StringStringable) getCurrentDestinationValue(markupItem.getAssociation(),
					destinationAddress);
			String destinationComment = destinationValue.getString();
			comment = StringUtilities.mergeStrings(destinationComment, sourceComment);
		}

		int commentType = getCodeUnitCommentType();
		Listing destinationListing = getDestinationListing(markupItem.getAssociation());
		destinationListing.setComment(destinationAddress, commentType, comment);
		return true;
	}

	private String getDestinationComment(VTAssociation association, Address destinationAddress) {
		if (destinationAddress != null && destinationAddress != Address.NO_ADDRESS) {
			int commentType = getCodeUnitCommentType();
			Listing destinationListing = getDestinationListing(association);
			return destinationListing.getComment(commentType, destinationAddress);
		}
		return null;
	}

	@Override
	public Stringable getCurrentDestinationValue(VTAssociation association,
			Address destinationAddress) {
		return new StringStringable(getDestinationComment(association, destinationAddress));
	}

	@Override
	public Stringable getOriginalDestinationValue(VTAssociation association,
			Address destinationAddress) {
		Stringable appliedMarkupOriginalValue = null;
		try {
			appliedMarkupOriginalValue = getOriginalDestinationValueForAppliedMarkupOfThisType(
				association, destinationAddress, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// For now this shouldn't get a cancel.
			// If it does then this falls through to the getDestinationValue() call.
		}
		if (appliedMarkupOriginalValue != null) {
			return appliedMarkupOriginalValue;
		}
		return getCurrentDestinationValue(association, destinationAddress);
	}

	@Override
	public boolean hasSameSourceAndDestinationValues(VTMarkupItem markupItem) {
		VTAssociation association = markupItem.getAssociation();
		Address sourceAddress = markupItem.getSourceAddress();
		Address destinationAddress = markupItem.getDestinationAddress();
		// Show comments that don't yet have a destination.
		if (destinationAddress == null || destinationAddress == Address.NO_ADDRESS) {
			return false;
		}
		String sourceComment = getSourceComment(association, sourceAddress);
		String destinationComment = getDestinationComment(association, destinationAddress);
		// Don't show comments that are the same.
		return SystemUtilities.isEqual(sourceComment, destinationComment);
	}

	@Override
	public boolean supportsApplyAction(VTMarkupItemApplyActionType applyAction) {
		return applyAction == VTMarkupItemApplyActionType.ADD ||
			applyAction == VTMarkupItemApplyActionType.REPLACE;
	}
}
