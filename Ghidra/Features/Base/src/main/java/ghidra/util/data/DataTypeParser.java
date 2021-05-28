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
package ghidra.util.data;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.services.DataTypeQueryService;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

public class DataTypeParser {

	public enum AllowedDataTypes {
		/**
		 * All data-types are permitted (excluding bitfields)
		 */
		ALL,
		/**
		 * All data-types, excluding factory data-types are permitted
		 */
		DYNAMIC,
		/**
		 * All fixed-length data-types and sizable Dynamic(i.e., canSpecifyLength) data-types
		 */
		SIZABLE_DYNAMIC,
		/**
		 * All fixed-length data-types, sizable Dynamic data-types.
		 * In addition a bitfield specification may be specified (e.g., int:2) 
		 * for use when defining structure and union components only
		 * (see {@link ProxyBitFieldDataType}).  Parser must be properly constructed
		 * with the intended {@link DataTypeParser#destinationDataTypeManager}.
		 * If a bitfield is returned special handling is required.
		 */
		SIZABLE_DYNAMIC_AND_BITFIELD,
		/**
		 * Only Fixed-length data-types
		 */
		FIXED_LENGTH,
		/**
		 * Only Fixed-length data types and string data types
		 */
		STRINGS_AND_FIXED_LENGTH,
		/**
		 * Only Enums, Integer types and those Typedefs based on them
		 * for use as a bitfield base datatype
		 */
		BITFIELD_BASE_TYPE
	}

	/**
	 * <code>ProxyBitFieldDataType</code> provides acts as a proxy bitfield
	 * whose specification may be used when defining a structure or 
	 * union bitfield.  This datatype may not be directly applied to a program. 
	 */
	private static class ProxyBitFieldDataType extends BitFieldDataType {
		/**
		 * Construct proxy bitfield datatype for use when defining 
		 * a structure or union bitfield.
		 * @param baseDataType a supported primitive integer data type or TypeDef to such a type.
		 * A deep clone of this type will be performed using the specified dataMgr.
		 * @param bitSize size of bit-field expressed as number of bits
		 * @throws InvalidDataTypeException if specified baseDataType is not permitted
		 */
		private ProxyBitFieldDataType(DataType baseDataType, int bitSize)
				throws InvalidDataTypeException {
			super(baseDataType, bitSize);
		}
	}

	private DataTypeManager sourceDataTypeManager;			// may be null
	private DataTypeManager destinationDataTypeManager;		// may be null
	private DataTypeQueryService dataTypeManagerService;	// may be null
	private AllowedDataTypes allowedTypes;

	/**
	 * A constructor that does not use the source or destination data type managers.  In terms of
	 * the source data type manager, this means that all data type managers will be used when
	 * resolving data types.
	 *
	 * @param dataTypeManagerService data-type manager tool service, or null
	 * @param allowedTypes constrains which data-types may be parsed 
	 */
	public DataTypeParser(DataTypeQueryService dataTypeManagerService,
			AllowedDataTypes allowedTypes) {
		this.dataTypeManagerService = dataTypeManagerService;
		this.allowedTypes = allowedTypes;
	}

	/**
	 * Constructor
	 * @param sourceDataTypeManager preferred source data-type manager, or null
	 * @param destinationDataTypeManager target data-type manager, or null
	 * @param dataTypeManagerService data-type manager tool service, or null
	 * @param allowedTypes constrains which data-types may be parsed
	 *
	 * @see #DataTypeParser(DataTypeQueryService, AllowedDataTypes)
	 */
	public DataTypeParser(DataTypeManager sourceDataTypeManager,
			DataTypeManager destinationDataTypeManager,
			DataTypeQueryService dataTypeManagerService, AllowedDataTypes allowedTypes) {
		this.sourceDataTypeManager = sourceDataTypeManager;
		this.destinationDataTypeManager = destinationDataTypeManager;
		this.dataTypeManagerService = dataTypeManagerService;
		this.allowedTypes = allowedTypes;
	}

	/**
	 * Parse a data-type string specification
	 * @param dataTypeString a known data-type name followed by zero or more pointer/array decorations.
	 * @return parsed data-type or null if not found
	 * @throws InvalidDataTypeException if data-type string is invalid or length exceeds specified maxSize
	 * @throws CancelledException parse cancelled through user interaction
	 */
	public DataType parse(String dataTypeString)
			throws InvalidDataTypeException, CancelledException {
		return parse(dataTypeString, (CategoryPath) null);
	}

	/**
	 * Parse a data type string specification with category path.  If category is not null,
	 * the dataTypeManagerService will not be queried.
	 * @param dataTypeString a known data-type name followed by zero or more pointer/array decorations.
	 * @param category known path of data-type or null if unknown
	 * @return parsed data-type or null if not found
	 * @throws InvalidDataTypeException if data type string is invalid or length exceeds specified 
	 *         maxSize
	 * @throws CancelledException parse cancelled through user interaction (only if parser 
	 *         constructed with service)
	 */
	public DataType parse(String dataTypeString, CategoryPath category)
			throws InvalidDataTypeException, CancelledException {
		dataTypeString = dataTypeString.replaceAll("\\s+", " ").trim();
		String dataTypeName = getBaseString(dataTypeString);
		DataType namedDt = getNamedDataType(dataTypeName, category);
		if (namedDt == null) {
			throw new InvalidDataTypeException("Valid data-type not specified");
		}
		return parseDataTypeModifiers(namedDt, dataTypeString.substring(dataTypeName.length()));
	}

	/**
	 * Parse a data type string specification using the specified baseDatatype.
	 * 
	 * @param suggestedBaseDataType base data type (may be null), this will be used as the base 
	 *        data-type if its name matches the base name in the specified dataTypeString.
	 * @param dataTypeString a base data-type followed by a sequence of zero or more pointer/array 
	 *        decorations to be applied.
	 * The string may start with the baseDataType's name.
	 * @return parsed data-type or null if not found
	 * @throws InvalidDataTypeException if data-type string is invalid or length exceeds specified 
	 *         maxSize
	 * @throws CancelledException parse cancelled through user interaction (only if parser 
	 *         constructed with service)
	 */
	public DataType parse(String dataTypeString, DataType suggestedBaseDataType)
			throws InvalidDataTypeException, CancelledException {
		dataTypeString = dataTypeString.replaceAll("\\s+", " ").trim();
		String dataTypeName = getBaseString(dataTypeString);
		if (StringUtils.isBlank(dataTypeName)) {
			throw new InvalidDataTypeException("missing base data-type name");
		}

		DataType namedDt;
		if (suggestedBaseDataType != null && dataTypeName.equals(suggestedBaseDataType.getName())) {
			namedDt = suggestedBaseDataType;
			if (namedDt.getDataTypeManager() != destinationDataTypeManager) {
				namedDt = namedDt.clone(destinationDataTypeManager);
			}
		}
		else {
			namedDt = getNamedDataType(dataTypeName, null);
			if (namedDt == null) {
				throw new InvalidDataTypeException("valid data-type not specified");
			}
		}

		return parseDataTypeModifiers(namedDt, dataTypeString.substring(dataTypeName.length()));
	}

	/**
	 * Throws exception if the data type does not match the specified {@link AllowedDataTypes}.
	 * 
	 * @param dt {@link DataType} to check
	 * @param allowedTypes {@link AllowedDataTypes enum} specifying what category of data types are ok
	 * @throws InvalidDataTypeException if dt violates the specified allowedTypes
	 */
	public static void ensureIsAllowableType(DataType dt, AllowedDataTypes allowedTypes)
			throws InvalidDataTypeException {
		if (dt instanceof BitFieldDataType) {
			if (allowedTypes != AllowedDataTypes.SIZABLE_DYNAMIC_AND_BITFIELD) {
				throw new InvalidDataTypeException("Bitfield data-type not allowed");
			}
			return;
		}
		switch (allowedTypes) {
			case DYNAMIC:
				if (dt instanceof FactoryDataType) {
					throw new InvalidDataTypeException("Factory data-type not allowed");
				}
				break;
			case SIZABLE_DYNAMIC:
			case SIZABLE_DYNAMIC_AND_BITFIELD:
				if (dt instanceof FactoryDataType) {
					throw new InvalidDataTypeException("Factory data-type not allowed");
				}
				if (dt instanceof Dynamic && !((Dynamic) dt).canSpecifyLength()) {
					throw new InvalidDataTypeException("non-sizable data-type not allowed");
				}
				break;
			case FIXED_LENGTH:
				if (dt.getLength() < 0) {
					throw new InvalidDataTypeException("Fixed-length data-type required");
				}
				break;
			case STRINGS_AND_FIXED_LENGTH:
				if (dt.getLength() < 0 && !(dt instanceof AbstractStringDataType)) {
					throw new InvalidDataTypeException("Fixed-length or string data-type required");
				}
				break;
			case BITFIELD_BASE_TYPE:
				if (!BitFieldDataType.isValidBaseDataType(dt)) {
					throw new InvalidDataTypeException(
						"Enum or integer derived data-type required");
				}
				break;
			case ALL:
				// do nothing
				break;
			default:
				throw new InvalidDataTypeException(
					"Unknown data type allowance specified: " + allowedTypes);
		}
	}

	private DataType parseDataTypeModifiers(DataType namedDataType, String dataTypeModifiers)
			throws InvalidDataTypeException {

		List<DtPiece> modifiers = parseModifiers(dataTypeModifiers);
		DataType dt = namedDataType;
		int elementLength = dt.getLength();
		try {
			for (DtPiece modifier : modifiers) {
				if (modifier instanceof PointerSpecPiece) {
					int pointerSize = ((PointerSpecPiece) modifier).getPointerSize();
					dt = new PointerDataType(dt, pointerSize, destinationDataTypeManager);
					elementLength = dt.getLength();
				}
				else if (modifier instanceof ElementSizeSpecPiece) {
					if (elementLength <= 0) {
						elementLength = ((ElementSizeSpecPiece) modifier).getElementSize();
					}
				}
				else if (modifier instanceof ArraySpecPiece) {
					int elementCount = ((ArraySpecPiece) modifier).getElementCount();
					dt = createArrayDataType(dt, elementLength, elementCount);
					elementLength = dt.getLength();
				}
				else if (modifier instanceof BitfieldSpecPiece) {
					if (allowedTypes != AllowedDataTypes.SIZABLE_DYNAMIC_AND_BITFIELD) {
						throw new InvalidDataTypeException("Bitfield not permitted");
					}
					if (destinationDataTypeManager == null) {
						throw new AssertException(
							"Bitfields require destination datatype manager to be specified");
					}
					int bitSize = ((BitfieldSpecPiece) modifier).getBitSize();
					dt = new ProxyBitFieldDataType(dt.clone(destinationDataTypeManager), bitSize);
				}
			}
		}
		catch (IllegalArgumentException e) {
			throw new InvalidDataTypeException(e.getMessage());
		}
		ensureIsAllowableType(dt, allowedTypes);
		return dt;
	}

	private List<DtPiece> parseModifiers(String dataTypeModifiers) throws InvalidDataTypeException {

		int arrayStartIndex = -1;
		List<DtPiece> modifiers = new ArrayList<>();
		boolean terminalModifier = false;
		for (String piece : splitDataTypeModifiers(dataTypeModifiers)) {
			piece = piece.trim();
			if (terminalModifier) {
				throw new InvalidDataTypeException("Invalid data type modifier");
			}
			if (piece.startsWith("*")) {
				modifiers.add(new PointerSpecPiece(piece));
				arrayStartIndex = -1;
			}
			else if (piece.startsWith("[")) {
				// group of array specifications are reversed for proper data-type creation order
				ArraySpecPiece arraySpec = new ArraySpecPiece(piece);
				if (arrayStartIndex >= 0) {
					modifiers.add(arrayStartIndex, arraySpec);
				}
				else {
					arrayStartIndex = modifiers.size();
					modifiers.add(arraySpec);
				}
			}
			else if (piece.startsWith(":")) {
				terminalModifier = true;
				modifiers.add(new BitfieldSpecPiece(piece));
			}
			else if (piece.startsWith("{")) {
				// # indicates the size of an array element when the base data type is dynamic.
				modifiers.add(new ElementSizeSpecPiece(piece));
				arrayStartIndex = -1;
			}
		}
		return modifiers;
	}

	private DataType getNamedDataType(String baseName, CategoryPath category)
			throws InvalidDataTypeException, CancelledException {

		List<DataType> results = new ArrayList<>();
		DataType dt = findDataType(sourceDataTypeManager, baseName, category, results);
		if (dt != null) {
			return dt; // found a direct match
		}

		//
		// We now either have no results or multiple results
		//
		if (results.isEmpty() && DataType.DEFAULT.getDisplayName().equals(baseName)) {
			dt = DataType.DEFAULT;
		}
		else if (category == null) {
			dt = findDataTypeInAllDataTypeManagers(baseName, results);
		}

		if (dt == null) {
			String msg = "Unrecognized data type of \"" + baseName + "\"";
			throw new InvalidDataTypeException(msg);
		}

		return dt.clone(destinationDataTypeManager);
	}

	private DataType findDataTypeInAllDataTypeManagers(String baseName, List<DataType> results)
			throws CancelledException {
		if (results.isEmpty() && dataTypeManagerService != null) {
			results.addAll(
				DataTypeUtils.getExactMatchingDataTypes(baseName, dataTypeManagerService));
		}

		if (results.isEmpty()) {
			return null;
		}

		// try to heuristically pick the right type
		DataType dt = pickFromPossibleEquivalentDataTypes(results);
		if (dt != null) {
			return dt;
		}

		// give up and ask the user
		return proptUserForType(baseName);

	}

	private DataType proptUserForType(String baseName) throws CancelledException {

		if (dataTypeManagerService == null) {
			return null;
		}

		DataType dt = dataTypeManagerService.getDataType(baseName);
		if (dt == null) {
			throw new CancelledException();
		}
		return dt;
	}

	private DataType findDataType(DataTypeManager dtm, String baseName, CategoryPath category,
			List<DataType> list) {

		DataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
		if (dtm == null) {
			// no DTM specified--try the built-ins
			return findDataType(builtInDTM, baseName, category, list);
		}

		if (category != null) {
			DataType dt = dtm.getDataType(category, baseName);
			if (dt != null) {
				list.add(dt);
				return dt;
			}
		}
		else {

			// handle C primitives (e.g.  long long, unsigned long int, etc.)
			DataType dataType = DataTypeUtilities.getCPrimitiveDataType(baseName);
			if (dataType != null) {
				return dataType;
			}

			dtm.findDataTypes(baseName, list);
			if (list.size() == 1) {
				return list.get(0);
			}
		}

		// nothing found--try the built-ins if we haven't yet
		if (list.isEmpty() && dtm != builtInDTM) {
			return findDataType(builtInDTM, baseName, category, list);
		}

		return null;
	}

	// ultimately, if one of the types is from the program or the builtin types, *and* the rest of
	// the data types are equivalent to that one, then this method returns that data type
	private static DataType pickFromPossibleEquivalentDataTypes(List<DataType> dtList) {

		DataType programDataType = null;

		// see if one of the data types belongs to the program or the built in types, where the
		// program is more important than the builtin
		for (DataType dataType : dtList) {
			DataTypeManager manager = dataType.getDataTypeManager();
			if (manager instanceof BuiltInDataTypeManager) {
				programDataType = dataType;
			}
			else if (manager instanceof ProgramDataTypeManager) {
				programDataType = dataType;
				break;
			}
		}

		if (programDataType == null) {
			return null;
		}

		for (DataType dataType : dtList) {
			// just one non-matching case means that we can't use the program's data type
			if (!programDataType.isEquivalent(dataType)) {
				return null;
			}
		}

		return programDataType;
	}

	private static String getBaseString(String dataTypeString) {
		int nextIndex = 0;
		int templateCount = 0;
		while (nextIndex < dataTypeString.length()) {
			char c = dataTypeString.charAt(nextIndex);
			if (c == '<') {
				templateCount++;
			}
			else if (c == '>') {
				templateCount--;
			}

			if (templateCount != 0) {
				++nextIndex;
				continue;
			}

			if (c == '*' || c == '[' || c == ':' || c == '{') {
				return dataTypeString.substring(0, nextIndex).trim();
			}
			++nextIndex;
		}
		return dataTypeString;
	}

	private static String[] splitDataTypeModifiers(String dataTypeModifiers) {
		dataTypeModifiers = dataTypeModifiers.replaceAll(":[ \\t]", "");
		if (dataTypeModifiers.length() == 0) {
			return new String[0];
		}
		List<String> list = new ArrayList<>();
		int startIndex = 0;
		int nextIndex = 1;
		while (nextIndex < dataTypeModifiers.length()) {
			char c = dataTypeModifiers.charAt(nextIndex);
			if (c == '*' || c == '[' || c == ':' || c == '{') {
				list.add(dataTypeModifiers.substring(startIndex, nextIndex));
				startIndex = nextIndex;
			}
			++nextIndex;
		}
		list.add(dataTypeModifiers.substring(startIndex, nextIndex));
		String[] pieces = new String[list.size()];
		list.toArray(pieces);
		return pieces;
	}

	private DataType createArrayDataType(DataType baseDataType, int elementLength, int elementCount)
			throws InvalidDataTypeException {
		DataType dt = baseDataType;
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (elementLength <= 0) {
			throw new InvalidDataTypeException(
				"Only a datatype with a positive size be used for an array: " +
					baseDataType.getName() + "; " + elementLength);
		}
		return new ArrayDataType(baseDataType, elementCount, elementLength,
			destinationDataTypeManager);
	}

	private static int parseSize(String size) {

		if (StringUtils.isBlank(size)) {
			throw new NumberFormatException();
		}
		size = size.trim();
		if (StringUtils.startsWithIgnoreCase(size, "0x")) {
			return Integer.parseInt(size.substring(2), 16);
		}
		return Integer.parseInt(size);
	}

	private static interface DtPiece {
		// dummy interface so we don't have to use Object in the list container
	}

	private static class BitfieldSpecPiece implements DtPiece {
		int bitSize;

		BitfieldSpecPiece(String piece) throws InvalidDataTypeException {
			if (piece.startsWith(":")) {
				String bitSizeStr = piece.substring(1);
				try {
					bitSize = parseSize(bitSizeStr);
					if (bitSize >= 0) {
						return;
					}
				}
				catch (NumberFormatException e) {
					// handled below
				}
			}
			throw new InvalidDataTypeException("Invalid bitfield specification: " + piece);
		}

		int getBitSize() {
			return bitSize;
		}
	}

	private static class ArraySpecPiece implements DtPiece {
		int elementCount;

		ArraySpecPiece(String piece) throws InvalidDataTypeException {
			if (piece.startsWith("[") && piece.endsWith("]")) {
				String elementCountStr = piece.substring(1, piece.length() - 1);
				try {
					elementCount = parseSize(elementCountStr);
					return;
				}
				catch (NumberFormatException e) {
					// handled below
				}
			}
			throw new InvalidDataTypeException("Invalid array specification: " + piece);
		}

		int getElementCount() {
			return elementCount;
		}
	}

	private static class PointerSpecPiece implements DtPiece {
		int pointerSize = -1;

		PointerSpecPiece(String piece) throws InvalidDataTypeException {
			if (!piece.startsWith("*")) {
				throw new InvalidDataTypeException("Invalid pointer specification: " + piece);
			}
			if (piece.length() == 1) {
				return;
			}
			try {
				pointerSize = Integer.parseInt(piece.substring(1));
			}
			catch (NumberFormatException e) {
				throw new InvalidDataTypeException("Invalid pointer specification: " + piece);
			}
			int mod = pointerSize % 8;
			pointerSize = pointerSize / 8;
			if (mod != 0 || pointerSize <= 0 || pointerSize > 8) {
				throw new InvalidDataTypeException("Invalid pointer size: " + piece);
			}
		}

		int getPointerSize() {
			return pointerSize;
		}
	}

	private static class ElementSizeSpecPiece implements DtPiece {
		int elementSize;

		ElementSizeSpecPiece(String piece) throws InvalidDataTypeException {
			if (piece.startsWith("{") && piece.endsWith("}")) {
				String elementSizeStr = piece.substring(1, piece.length() - 1);
				try {
					elementSize = parseSize(elementSizeStr);
					return;
				}
				catch (NumberFormatException e) {
					// handled below
				}
			}
			throw new InvalidDataTypeException(
				"Invalid array element size specification: " + piece);
		}

		int getElementSize() {
			return elementSize;
		}
	}
}
