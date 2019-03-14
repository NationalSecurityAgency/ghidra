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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import javax.swing.event.ChangeEvent;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.plugin.core.navigation.FunctionUtils;
import ghidra.app.util.viewer.field.*;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A location descriptor that should be extended by location descriptor implementations that 
 * are based upon data types.
 */
abstract class DataTypeLocationDescriptor extends LocationDescriptor {

	protected DataType originalDataType; // the one passed in at construction time
	protected DataType baseDataType; // the one used to find references (could be a base type)
	protected String dataTypeName;   // e.g., Foo or Foo.bar.baz

	DataTypeLocationDescriptor(ProgramLocation location, Program program) {
		super(location, program);

		if (location == null) {
			throw new NullPointerException(
				"Cannot create a LocationDescriptor from a null ProgramLocation");
		}

		originalDataType = getSourceDataType();
		homeAddress = location.getAddress();
		baseDataType = loadDataType();
		label = generateLabel();
		dataTypeName = getDataTypeName();
	}

	@Override
	public String getTypeName() {
		return dataTypeName;
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {
		findDataTypeReferences(accumulator, monitor);
	}

	/** The original data type that this location descriptor describes */
	protected abstract DataType getSourceDataType();

	/** Generates the label for the results window */
	protected abstract String generateLabel();

	/** Returns the name of the data type, for example, 'Foo' or 'Foo.bar.baz' */
	protected abstract String getDataTypeName();

	/** 
	 * The base data type that this location descriptor describes (this may be the same as the
	 * original data type.
	 */
	protected DataType getBaseDataType() {
		return getSourceDataType(); // by default these two values are the same
	}

	private void findDataTypeReferences(Accumulator<LocationReference> accumulator,
			TaskMonitor monitor) throws CancelledException {

		DataType currentDataType = getDataType();
		ReferenceUtils.findDataTypeReferences(accumulator, currentDataType, null, program,
			useDynamicSearching, monitor);
	}

	private DataType loadDataType() {
		if (baseDataType == null) {
			baseDataType = getBaseDataType();
		}
		return baseDataType;
	}

	protected DataType getDataType() {
		if (baseDataType instanceof Structure) {
			Data data = getData(getLocation());
			if (data != null) {
				return ReferenceUtils.getBaseDataType(data.getDataType());
			}
		}

		return ReferenceUtils.getBaseDataType(baseDataType);
	}

	protected Data getData(ProgramLocation location) {
		Listing listing = program.getListing();
		Address address = location.getAddress();
		Data data = listing.getDataContaining(address);
		if (data != null) {
			return data.getComponent(location.getComponentPath());
		}

		return null;
	}

	@Override
	protected boolean domainObjectChanged(DomainObjectChangedEvent changeEvent) {

		for (int i = 0; i < changeEvent.numRecords(); i++) {
			DomainObjectChangeRecord domainObjectRecord = changeEvent.getChangeRecord(i);
			int eventType = domainObjectRecord.getEventType();

			switch (eventType) {
				case ChangeManager.DOCR_FUNCTION_CHANGED:
					ProgramChangeRecord changeRecord = (ProgramChangeRecord) domainObjectRecord;
					Address functionAddress = changeRecord.getStart();
					if (referencesContain(functionAddress) &&
						functionContainsDataType(functionAddress)) {
						return checkForAddressChange(changeRecord);
					}
					break;

				case ChangeManager.DOCR_MEMORY_BLOCK_MOVED:
				case ChangeManager.DOCR_MEMORY_BLOCK_REMOVED:
				case ChangeManager.DOCR_SYMBOL_REMOVED:
				case ChangeManager.DOCR_MEM_REFERENCE_REMOVED:
				case ChangeManager.DOCR_CODE_REMOVED:
				case ChangeManager.DOCR_FUNCTION_REMOVED:
				case ChangeManager.DOCR_VARIABLE_REFERENCE_REMOVED:
				case DomainObject.DO_OBJECT_RESTORED:
					return checkForAddressChange(domainObjectRecord);
				case ChangeManager.DOCR_CODE_ADDED:
				case ChangeManager.DOCR_MEMORY_BLOCK_ADDED:
				case ChangeManager.DOCR_SYMBOL_ADDED:
				case ChangeManager.DOCR_MEM_REFERENCE_ADDED:
				case ChangeManager.DOCR_FUNCTION_ADDED:
				case ChangeManager.DOCR_VARIABLE_REFERENCE_ADDED:
				case ChangeManager.DOCR_DATA_TYPE_RENAMED:
				case ChangeManager.DOCR_DATA_TYPE_REPLACED:
					// signal that the reference addresses may be out-of-date
					if (modelFreshnessListener != null) {
						modelFreshnessListener.stateChanged(new ChangeEvent(this));
					}
					return true;
			}
		}

		return false;
	}

	private boolean functionContainsDataType(Address functionAddress) {
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(functionAddress);
		DataType currentDataType = getDataType();
		if (function != null) {
			List<Variable> allVariables = ReferenceUtils.getVariables(function, true);
			for (Variable variable : allVariables) {
				DataType variableDataType = variable.getDataType();
				if (ReferenceUtils.getBaseDataType(variableDataType).isEquivalent(
					currentDataType)) {
					return true;
				}
			}

			DataType returnType = function.getReturnType();
			if (ReferenceUtils.getBaseDataType(returnType).isEquivalent(currentDataType)) {
				return true;
			}
		}

		return false;
	}

	@Override
	Highlight[] getHighlights(String text, Object object,
			Class<? extends FieldFactory> fieldFactoryClass, Color highlightColor) {

		Address currentAddress = getAddressForHighlightObject(object);
		if (!isInAddresses(currentAddress)) {
			return EMPTY_HIGHLIGHTS;
		}

		if (MnemonicFieldFactory.class.isAssignableFrom(fieldFactoryClass) &&
			(object instanceof Data)) {
			// compare against the underlying datatype, since the display text is different
			Data data = (Data) object;
			DataType otherBaseDataType = ReferenceUtils.getBaseDataType(data.getDataType());
			if (otherBaseDataType.isEquivalent(baseDataType)) {
				Highlight[] dtHighlights = getMnemonicDataTypeHighlights(text, highlightColor);
				return dtHighlights;
			}
		}
		else if (MnemonicFieldFactory.class.isAssignableFrom(fieldFactoryClass) ||
			OperandFieldFactory.class.isAssignableFrom(fieldFactoryClass) ||
			VariableTypeFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {

			String highlightText = getHighlightStringForDataTypeName(text);
			if (highlightText != null) {
				return new Highlight[] {
					new Highlight(0, highlightText.length() - 1, highlightColor) };
			}
		}
		else if (FunctionSignatureFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {
			// pull out the matching pieces of the data type
			List<Highlight> list = new ArrayList<>();

			Function function = (Function) object;
			FieldStringInfo returnTypeStringInfo =
				FunctionUtils.getFunctionReturnTypeStringInfo(function, text);
			String returnTypeString = returnTypeStringInfo.getFieldString();
			if (label.equals(returnTypeString)) {
				int offset = returnTypeStringInfo.getOffset();
				list.add(
					new Highlight(offset, offset + returnTypeString.length() - 1, highlightColor));
			}

			FieldStringInfo[] parameterStringInfos =
				FunctionUtils.getFunctionParameterStringInfos(function, text);
			for (FieldStringInfo info : parameterStringInfos) {
				String paramString = info.getFieldString();
				String highlightText = getHighlightStringForParameterDeclaration(paramString);
				if (highlightText != null) {
					int offset = info.getOffset();
					int length = offset + highlightText.length() - 1;
					list.add(new Highlight(offset, length, highlightColor));
				}
			}

			return list.toArray(new Highlight[list.size()]);
		}

		return EMPTY_HIGHLIGHTS;
	}

	protected Highlight[] getMnemonicDataTypeHighlights(String mnemonicText, Color highlightColor) {
		return new Highlight[] { new Highlight(0, mnemonicText.length() - 1, highlightColor) };
	}

	// returns null if there is no match
	private String getHighlightStringForParameterDeclaration(String parameterDeclaration) {
		String[] paramParts = parameterDeclaration.split("\\s");
		String paramName = paramParts[0];
		if (label.equals(paramName)) {
			return paramName;
		}
		// check for pointer names
		else if (label.endsWith("*") && label.startsWith(paramName)) {
			// see if we need to chop off some '*'s, as we may have searched for a pointer to a 
			// pointer and have found a match against a simple pointer and thus the display may 
			// not match our label
			if (paramParts.length == 1) {
				return paramName; // not a full declaration, just the name
			}

			String variableName = paramParts[paramParts.length - 1];
			int variableNameOffset = parameterDeclaration.indexOf(variableName);
			if (label.length() > variableNameOffset) {
				return label.substring(0, variableNameOffset - 1); // -1 for the space before the name
			}

			return label;
		}

		return null;
	}

	private String getHighlightStringForDataTypeName(String listingDisplayText) {

		if (dataTypeName.equals(listingDisplayText)) {
			return listingDisplayText;
		}

		// check for pointer names
		if (dataTypeName.endsWith("*") && dataTypeName.startsWith(listingDisplayText)) {
			return listingDisplayText;
		}
		else if (listingDisplayText.startsWith(dataTypeName) && listingDisplayText.endsWith("*")) {
			return dataTypeName;
		}

		return null;
	}
}
