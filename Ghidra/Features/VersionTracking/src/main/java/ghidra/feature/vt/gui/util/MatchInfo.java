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
package ghidra.feature.vt.gui.util;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.*;
import ghidra.feature.vt.gui.plugin.AddressCorrelatorManager;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

import java.util.*;

public class MatchInfo {

	private final VTMatch match;
	private final Program sourceProgram;
	private final Program destinationProgram;
	private final Function sourceFunction;
	private final Function destinationFunction;
	private final Data sourceData;
	private final Data destinationData;
	private final AddressSetView sourceAddressSet;
	private final AddressSetView destinationAddressSet;
	private MarkupItemsCache markupItemsCache;
	private AddressCorrelation correlationCache;
	private boolean initCorrelationCache = true;
	private final AddressCorrelatorManager correlator;

	MatchInfo(VTController controller, VTMatch match, AddressCorrelatorManager correlator) {
		this.match = match;
		this.correlator = correlator;
		VTAssociation association = match.getAssociation();
		VTSession session = association.getSession();
		sourceProgram = session.getSourceProgram();
		destinationProgram = session.getDestinationProgram();
		markupItemsCache = new MarkupItemsCache();
		VTAssociationType type = association.getType();

		Address sourceAddress = association.getSourceAddress();
		sourceFunction =
			(sourceProgram != null) ? sourceProgram.getFunctionManager().getFunctionAt(
				sourceAddress) : null;
		if (type == VTAssociationType.FUNCTION && sourceFunction != null) {
			sourceData = null;
			sourceAddressSet = sourceFunction.getBody();
		}
		else {
			Listing sourceListing = sourceProgram.getListing();
			sourceData = sourceListing.getDataAt(sourceAddress);
			CodeUnit codeUnit = sourceListing.getCodeUnitAt(sourceAddress);
			if (codeUnit == null) {
				sourceAddressSet = new AddressSet(sourceAddress);
			}
			else {
				sourceAddressSet =
					new AddressSet(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
			}
		}

		Address destinationAddress = association.getDestinationAddress();
		destinationFunction =
			(destinationProgram != null) ? destinationProgram.getFunctionManager().getFunctionAt(
				destinationAddress) : null;
		if (type == VTAssociationType.FUNCTION && destinationFunction != null) {
			destinationData = null;
			destinationAddressSet = destinationFunction.getBody();
		}
		else {
			Listing destinationListing = destinationProgram.getListing();
			destinationData = destinationListing.getDataAt(destinationAddress);
			CodeUnit codeUnit = destinationListing.getCodeUnitAt(destinationAddress);
			if (codeUnit == null) {
				destinationAddressSet = new AddressSet(destinationAddress);
			}
			else {
				Address minAddress = codeUnit.getMinAddress();
				Address maxAddress = codeUnit.getMaxAddress();

				// Adjust the maxAddress for the destination addressSet to show multiple code units 
				// if it is smaller than the source. We want to know what gets overwritten if applied.
				if (destinationData != null) {
					int sourceLength = (sourceData != null) ? sourceData.getLength() : 0;
					int destinationLength = destinationData.getLength();
					if (sourceLength > destinationLength) {
						maxAddress = minAddress.add(sourceLength - 1);
					}
				}

				AddressSet tempDestinationAddressSet = new AddressSet(minAddress, maxAddress);
				// Intersect it with memory so the dual listing can show "address break" field, if any.
				destinationAddressSet =
					tempDestinationAddressSet.intersect(destinationProgram.getMemory());
			}
		}
	}

	public void clearCache() {
		markupItemsCache.clear();
	}

	public VTMatch getMatch() {
		return match;
	}

	public Function getSourceFunction() {
		return sourceFunction;
	}

	public Function getDestinationFunction() {
		return destinationFunction;
	}

	public Data getSourceData() {
		return sourceData;
	}

	public Data getDestinationData() {
		return destinationData;
	}

	public AddressSetView getSourceAddressSet() {
		return sourceAddressSet;
	}

	public AddressSetView getDestinationAddressSet() {
		return destinationAddressSet;
	}

	public Collection<VTMarkupItem> getAppliableMarkupItems(TaskMonitor monitor) {
		return markupItemsCache.get(monitor);
	}

	private void setDefaultDestination(VTMarkupItem markupItem,
			AddressCorrelation addressTranslator, TaskMonitor monitor) throws CancelledException {

		Address destinationAddress = getDestinationAddress(markupItem);
		Address sourceAddress = markupItem.getSourceAddress();

		if (destinationAddress != null) {
			return; // we already have a set destination address
		}

		String destinationAddressSource = null;
		if (addressTranslator != null) {
			AddressRange correlatedDestinationRange =
				addressTranslator.getCorrelatedDestinationRange(sourceAddress, monitor);
			if (correlatedDestinationRange != null) {
				destinationAddress = correlatedDestinationRange.getMinAddress();
				destinationAddressSource = addressTranslator.getName();
			}
		}

		if (destinationAddress != null) {
			markupItem.setDefaultDestinationAddress(destinationAddress, destinationAddressSource);
		}
	}

	private Address getDestinationAddress(VTMarkupItem markupItem) {
		ProgramLocation loc = markupItem.getDestinationLocation();
		return loc == null ? null : loc.getAddress();
	}

	private AddressCorrelation getAddressTranslator(AddressCorrelatorManager correlatorMgr) {
		if (initCorrelationCache) {
			VTAssociation association = match.getAssociation();
			VTAssociationType type = association.getType();
			if (type == VTAssociationType.FUNCTION) {
				if (!(sourceFunction == null || destinationFunction == null)) {
					correlationCache =
						correlatorMgr.getCorrelator(sourceFunction, destinationFunction);
				}
			}
			else if (type == VTAssociationType.DATA) {
				if (!(sourceData == null || destinationData == null)) {
					correlationCache = correlatorMgr.getCorrelator(sourceData, destinationData);
				}
			}
			initCorrelationCache = false;
		}
		return correlationCache;
	}

	public Address getDestinationAddress(Address sourceAddress,
			AddressCorrelatorManager correlatorMgr) {

		if (sourceAddress == null) {
			return null;
		}

		AddressCorrelation addressTranslator = getAddressTranslator(correlatorMgr);
		if (addressTranslator == null) {
			return null;
		}
		AddressRange correlatedDestinationRange = null;
		try {
			correlatedDestinationRange =
				addressTranslator.getCorrelatedDestinationRange(sourceAddress,
					TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// check for null below
		}
		if (correlatedDestinationRange == null) {
			return null;
		}
		return correlatedDestinationRange.getMinAddress();
	}

	public VTMarkupItem getCurrentMarkupForLocation(ProgramLocation programLocation, Program program) {

		VTMarkupType markupType = getMarkupTypeForLocation(programLocation, program);
		if (markupType == null) {
			return null;
		}
		Address markupAddress = getMarkupAddressForLocation(programLocation, program);

		return getMarkupItem(markupAddress, (program == sourceProgram), markupType);
	}

	private VTMarkupItem getMarkupItem(Address address, boolean isSourceAddress,
			VTMarkupType markupType) {
		if (address == null) {
			return null;
		}

		List<VTMarkupItem> list = markupItemsCache.getCachedValue();
		if (list == null) {
			// not sure how this could happen--perhaps after 
			// the cache has been cleared, before we are again loaded?
			return null;
		}

		for (VTMarkupItem markupItem : list) {
			ProgramLocation location =
				isSourceAddress ? markupItem.getSourceLocation()
						: markupItem.getDestinationLocation();
			if (location == null) {
				continue;
			}
			Address markupItemAddress =
				MatchInfo.getMarkupAddressForLocation(location, (isSourceAddress ? sourceProgram
						: destinationProgram));
			if (address.equals(markupItemAddress) && (markupItem.getMarkupType() == markupType)) {
				return markupItem;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " - " + match;
	}

	public static VTMarkupType getMarkupTypeForLocation(ProgramLocation programLocation,
			Program program) {
		if (programLocation instanceof FunctionNameFieldLocation) {
			return FunctionNameMarkupType.INSTANCE;
		}
		if (programLocation instanceof FunctionReturnTypeFieldLocation) {
//			return FunctionReturnTypeMarkupType.INSTANCE;
			return FunctionSignatureMarkupType.INSTANCE;
		}
		if (programLocation instanceof FunctionCallingConventionFieldLocation) {
			return FunctionSignatureMarkupType.INSTANCE;
		}
		if (programLocation instanceof FunctionInlineFieldLocation) {
			return FunctionSignatureMarkupType.INSTANCE;
//			return FunctionInlineMarkupType.INSTANCE;
		}
		if (programLocation instanceof FunctionNoReturnFieldLocation) {
			return FunctionSignatureMarkupType.INSTANCE;
//			return FunctionNoReturnMarkupType.INSTANCE;
		}
		if (programLocation instanceof FunctionSignatureFieldLocation) {
			FunctionSignatureFieldLocation functionSignatureLocation =
				(FunctionSignatureFieldLocation) programLocation;
			String signature = functionSignatureLocation.getSignature();
			if (signature.endsWith("...)")) {
				int index = functionSignatureLocation.getCharOffset();
				int startVarArgs = signature.length() - 4;
				int endVarArgs = startVarArgs + 2;
				if (index >= startVarArgs && index <= endVarArgs) {
					return FunctionSignatureMarkupType.INSTANCE;
				}
			}
		}
//		if ((programLocation instanceof FunctionParameterFieldLocation) ||
//			(programLocation instanceof FunctionStartParametersFieldLocation) ||
//			(programLocation instanceof FunctionEndParametersFieldLocation)) {
//			return ParametersSignatureMarkupType.INSTANCE;
//		}
		if (programLocation instanceof FunctionParameterFieldLocation) {
//			if (programLocation instanceof FunctionParameterNameFieldLocation) {
//				return ParameterNamesMarkupType.INSTANCE;
//			}
			return FunctionSignatureMarkupType.INSTANCE;
		}
		if (programLocation instanceof LabelFieldLocation) {
			return LabelMarkupType.INSTANCE;
		}
		if (programLocation instanceof FunctionNameFieldLocation) {
			return FunctionNameMarkupType.INSTANCE;
		}
		if ((programLocation instanceof EolCommentFieldLocation) ||
			(programLocation instanceof AutomaticCommentFieldLocation)) {
			return EolCommentMarkupType.INSTANCE;
		}
		if (programLocation instanceof PlateFieldLocation) {
			return PlateCommentMarkupType.INSTANCE;
		}
		if (programLocation instanceof PostCommentFieldLocation) {
			return PostCommentMarkupType.INSTANCE;
		}
		if (programLocation instanceof RepeatableCommentFieldLocation) {
			return RepeatableCommentMarkupType.INSTANCE;
		}
		if (programLocation instanceof CommentFieldLocation) { // This must follow other comment location checks.
			return PreCommentMarkupType.INSTANCE;
		}
		if (programLocation instanceof MnemonicFieldLocation) {
			return DataTypeMarkupType.INSTANCE;
		}
		if (programLocation instanceof VariableLocation) {
			VariableLocation variableLocation = (VariableLocation) programLocation;
			Variable variable = variableLocation.getVariable();
			if (variable instanceof Parameter) {
				if (programLocation instanceof VariableNameFieldLocation) {
//					return FunctionParameterNameMarkupType.INSTANCE;
					VariableNameFieldLocation nameLoc = (VariableNameFieldLocation) programLocation;
					if (!nameLoc.isReturn()) {
//						return ParameterNamesMarkupType.INSTANCE;
						return FunctionSignatureMarkupType.INSTANCE;
					}
				}
				if (programLocation instanceof VariableCommentFieldLocation) {
//					return FunctionParameterCommentMarkupType.INSTANCE;
//					return ParameterNamesMarkupType.INSTANCE;
					return FunctionSignatureMarkupType.INSTANCE;
				}
				if (programLocation instanceof VariableTypeFieldLocation) {
//					return FunctionParameterDataTypeMarkupType.INSTANCE;
					return FunctionSignatureMarkupType.INSTANCE;
				}
				if (programLocation instanceof VariableLocFieldLocation) {
//					return FunctionParameterDataTypeMarkupType.INSTANCE;
					return FunctionSignatureMarkupType.INSTANCE;
				}
			}
//			if (programLocation instanceof VariableNameFieldLocation) {
//				return FunctionLocalVariableNameMarkupType.INSTANCE;
//			}
//			if (programLocation instanceof VariableCommentFieldLocation) {
//				return FunctionLocalVariableCommentMarkupType.INSTANCE;
//			}
//			if (programLocation instanceof VariableTypeFieldLocation) {
//				return FunctionLocalVariableDataTypeMarkupType.INSTANCE;
//			}
		}
		return null;
	}

	public static Address getMarkupAddressForLocation(ProgramLocation programLocation,
			Program program) {
//		if (programLocation instanceof VariableLocation) {
//			VariableLocation variableLocation = (VariableLocation) programLocation;
//			Variable variable = variableLocation.getVariable(program);
//			if (variable != null) {
//				return variable.getMinAddress();
//			}
//		}
		return programLocation.getAddress();
	}

	class MarkupItemsCache extends CachingSwingWorker<List<VTMarkupItem>> {

		public MarkupItemsCache() {
			super("Generating Markup Items", true);
		}

		@Override
		protected List<VTMarkupItem> runInBackground(TaskMonitor monitor) {
			List<VTMarkupItem> list = new ArrayList<VTMarkupItem>();
			VTAssociation association = match.getAssociation();

			try {
				Collection<VTMarkupItem> markupItems = association.getMarkupItems(monitor);
				AddressCorrelation addressTranslator = getAddressTranslator(correlator);

				for (VTMarkupItem markupItem : markupItems) {
					Address destinationAddress = markupItem.getDestinationAddress();
					if (destinationAddress == null) {
						setDefaultDestination(markupItem, addressTranslator, monitor);
					}
					list.add(markupItem);
				}

				return list;
			}
			catch (CancelledException e) {
				return new ArrayList<VTMarkupItem>();
			}

		}

	}
}
