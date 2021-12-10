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
package ghidra.app.plugin.core.compositeeditor;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;

/**
 * DataTypeHelper is a helper class for dealing with data types in the Composite
 * Data Type Editor (Structure or Union Editor). It provides static methods for 
 * use with the data type text field in the editor.
 * It also has a static method to prompt the user for the size of a data type.
 */
public class DataTypeHelper {

	/**
	 * Method stripWhiteSpace removes all blanks and control characters from
	 * the original string.
	 * @param original the original string
	 * @return String the string with blanks and control characters removed.
	 */
	public static String stripWhiteSpace(String original) {
		if (original == null) {
			return null;
		}
		int length = original.length();
		char[] result = new char[length];
		int origIndex = 0;
		int resultIndex = 0;
		for (; origIndex < length; origIndex++) {
			// Don't keep blanks or control characters which are less than a blank.
			char c = original.charAt(origIndex);
			if (c > ' ') {
				result[resultIndex++] = c;
			}
		}
		return new String(result, 0, resultIndex);
	}

	public static DataType resolveDataType(DataType dt, DataTypeManager resolveDtm,
			DataTypeConflictHandler conflictHandler) {
		int txID = 0;
		try {
			txID = resolveDtm.startTransaction("Apply data type \"" + dt.getName() + "\"");
			dt = resolveDtm.resolve(dt, conflictHandler);
		}
		finally {
			resolveDtm.endTransaction(txID, (dt != null));
		}
		return dt;
	}

	/**
	 * Parses a data type that was typed in the composite data type editor.
	 * It creates a DataTypeInstance that consists of the data type and its size.
	 * If there are multiple of the named data type, this method will ask the
	 * user to select the desired data type.
	 * If the data type size can't be determined, then the user is prompted for
	 * the appropriate size.
	 * @param index the component index being edited.
	 * @param dtValue the new data type to parse.
	 * @param editModel the model indicating the composite editor's state.
	 * @param dtManager the data type manager of the composite data type being edited.
	 * @param dtmService the data type manager service to use to determine the
	 * data type the user specified.
	 * @return the data type instance or null if the user canceled when prompted 
	 * for more information.
	 * @throws InvalidDataTypeException if the specified data type isn't valid.
	 * @throws UsrException if the specified data type can't be used at the 
	 * specified index in the composite.
	 */
	public static DataType parseDataType(int index, String dtValue, CompositeEditorModel editModel,
			DataTypeManager dtManager, DataTypeManagerService dtmService)
			throws InvalidDataTypeException, UsrException {

		String dtName = stripWhiteSpace(dtValue);
		if ((dtName == null) || (dtName.length() < 1)) {
			throw new InvalidDataTypeException("No data type was specified.");
		}
		DataTypeParser dtp = new DataTypeParser(dtManager, editModel.viewDTM, dtmService,
			AllowedDataTypes.SIZABLE_DYNAMIC);
		DataType newDt = dtp.parse(dtName);
		if (newDt == null) {
			throw new InvalidDataTypeException("valid data-type not specified");
		}
		editModel.checkIsAllowableDataType(newDt);
		int mrl = editModel.getMaxReplaceLength(index);
		if ((mrl != -1) && (newDt.getLength() > mrl)) {
			throw new InvalidDataTypeException(newDt.getDisplayName() + " doesn't fit within " +
				mrl + " bytes, need " + newDt.getLength() + " bytes");
		}
		return newDt;
	}

	static DataTypeInstance getSizedDataType(CompositeEditorProvider provider, DataType dt,
			int defaultSize, int maxSize) throws InvalidDataTypeException {
		if (dt instanceof FactoryDataType) {
			throw new InvalidDataTypeException("Factory data types are not allowed.");
		}
		else if (dt instanceof Dynamic && !((Dynamic) dt).canSpecifyLength()) {
			throw new InvalidDataTypeException("Non-sizable Dynamic data types are not allowed.");
		}

		// A function definition can't be directly applied, only a pointer to the function definition.
		// Convert any function definition to a pointer. Otherwise, keep the original data type.
		boolean isFunctionDef = (dt instanceof FunctionDefinition);
		if (dt instanceof TypeDef) {
			isFunctionDef = (((TypeDef) dt).getBaseDataType() instanceof FunctionDefinition);
		}
		if (isFunctionDef) {
			dt = new PointerDataType(dt, -1, dt.getDataTypeManager());
		}

		int dtLen = dt.getLength();
		if (dtLen == 0) {
			throw new InvalidDataTypeException("Data types of size 0 are not allowed.");
		}
		if ((dtLen < 0) && (dt instanceof Dynamic) && ((Dynamic) dt).canSpecifyLength()) {
			try {
				dtLen = requestDtSize(provider, dt.getDisplayName(), defaultSize, maxSize);
			}
			catch (CancelledException e) {
				return null;
			}
		}
		if (dtLen < 0) {
			throw new InvalidDataTypeException(
				"Data type " + dt.getDisplayName() + " has no size and is not allowed.");
		}
		return DataTypeInstance.getDataTypeInstance(dt, dtLen);
	}

	public static int requestDtSize(CompositeEditorProvider provider, String dtName,
			int defaultSize, int maxBytes) throws CancelledException {
		NumberInputDialog dtSizeDialog =
			new NumberInputDialog(dtName + " bytes", defaultSize, 1, maxBytes);
		String helpAnchor = provider.getHelpName() + "_" + "Bytes_NumberInputDialog";
		HelpLocation helpLoc = new HelpLocation(provider.getHelpTopic(), helpAnchor);
		dtSizeDialog.setHelpLocation(helpLoc);
		if (!dtSizeDialog.show()) {
			throw new CancelledException();
		}
		int resultBytes = dtSizeDialog.getValue();

		CompositeEditorModel model = provider.getModel();
		model.setLastNumBytes(resultBytes);

		return resultBytes;
	}

	/**
	 * Creates a fixed length data type from the one that is passed in.
	 * The user is prompted for a size, if the data type doesn't have a size.
	 * The valid size depends upon the current editor state and the component
	 * index where it will be located. If the data type is a valid size, it
	 * will be returned unchanged. If the user cancels from the size dialog,
	 * then a null is returned.
	 *
	 * @param index the component index of where to add the data type.
	 * @param dt the data type to add
	 *
	 * @return the data type and its size or null if the user canceled when 
	 * prompted for a size.
	 */
	public static DataTypeInstance getFixedLength(CompositeEditorModel model, int index,
			DataType dt) {
		if (dt instanceof FactoryDataType) {
			model.setStatus("Factory data types are not allowed in a composite data type.");
			return null;
		}
		if (dt instanceof Dynamic && !((Dynamic) dt).canSpecifyLength()) {
			model.setStatus(
				"Non-sizable Dynamic data types are not allowed in a composite data type.");
			return null;
		}
		if (dt.getLength() == 0) {
			model.setStatus("Data types of size 0 are not allowed.");
			return null;
		}

		int length = dt.getLength();
		// If pointer, string, etc. then need a length.
		if (length < 0) {
			int maxBytes = model.getMaxReplaceLength(index);
			return requestBytes(model, dt, maxBytes);
		}
		return DataTypeInstance.getDataTypeInstance(dt, length);
	}

	public static DataTypeInstance requestBytes(CompositeEditorModel model, DataType dt,
			int maxBytes) {
		CompositeEditorProvider provider = model.getProvider();
		DataType actualDt = dt;
		if (actualDt instanceof TypeDef) {
			actualDt = ((TypeDef) actualDt).getBaseDataType();
		}

		int maxDtBytes = maxBytes;
		int dtBytes = model.getLastNumBytes();
		dtBytes = ((maxDtBytes > 0) && (dtBytes > maxDtBytes)) ? maxDtBytes : dtBytes;

		int size;
		try {
			size = requestDtSize(provider, dt.getName(), dtBytes, maxDtBytes);
		}
		catch (CancelledException e) {
			return null;
		}

		if (size >= 1) {
			model.setLastNumBytes(size);
			return DataTypeInstance.getDataTypeInstance(dt, size);
		}
		return null;
	}

	static public DataType getBaseType(DataType dt) {
		DataType testTypeDefDt = dt;
		if (testTypeDefDt instanceof TypeDef) {
			return ((TypeDef) testTypeDefDt).getBaseDataType();
		}
		if (dt instanceof Array) {
			return ((Array) dt).getDataType();
		}
		else if (dt instanceof Pointer) {
			DataType pdt = ((Pointer) dt).getDataType();
			if (pdt == null) {
				return dt;
			}
			return pdt;
		}
		else {
			return dt;
		}
	}

}
