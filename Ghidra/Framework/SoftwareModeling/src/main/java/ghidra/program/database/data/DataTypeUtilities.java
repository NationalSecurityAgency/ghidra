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
package ghidra.program.database.data;

import java.util.*;
import java.util.regex.Pattern;

import ghidra.app.util.NamespaceUtils;
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.UniversalID;
import ghidra.util.exception.AssertException;

public class DataTypeUtilities {
	private static Map<String, DataType> cPrimitiveNameMap = new HashMap<>();
	static {
		cPrimitiveNameMap.put("char", CharDataType.dataType);
		cPrimitiveNameMap.put("signed char", CharDataType.dataType);
		cPrimitiveNameMap.put("unsigned char", UnsignedCharDataType.dataType);
		cPrimitiveNameMap.put("short", ShortDataType.dataType);
		cPrimitiveNameMap.put("short int", ShortDataType.dataType);
		cPrimitiveNameMap.put("signed short", ShortDataType.dataType);
		cPrimitiveNameMap.put("signed short int", ShortDataType.dataType);
		cPrimitiveNameMap.put("unsigned short", UnsignedShortDataType.dataType);
		cPrimitiveNameMap.put("unsigned short int", UnsignedShortDataType.dataType);
		cPrimitiveNameMap.put("int", IntegerDataType.dataType);
		cPrimitiveNameMap.put("signed", IntegerDataType.dataType);
		cPrimitiveNameMap.put("signed int", IntegerDataType.dataType);
		cPrimitiveNameMap.put("unsigned", UnsignedIntegerDataType.dataType);
		cPrimitiveNameMap.put("unsigned int", UnsignedIntegerDataType.dataType);
		cPrimitiveNameMap.put("long", LongDataType.dataType);
		cPrimitiveNameMap.put("long int", LongDataType.dataType);
		cPrimitiveNameMap.put("signed long", LongDataType.dataType);
		cPrimitiveNameMap.put("signed long int", LongDataType.dataType);
		cPrimitiveNameMap.put("unsigned long", UnsignedLongDataType.dataType);
		cPrimitiveNameMap.put("long long", LongLongDataType.dataType);
		cPrimitiveNameMap.put("long long int", LongLongDataType.dataType);
		cPrimitiveNameMap.put("signed long long", LongLongDataType.dataType);
		cPrimitiveNameMap.put("signed long long int", LongLongDataType.dataType);
		cPrimitiveNameMap.put("unsigned long long", UnsignedLongLongDataType.dataType);
		cPrimitiveNameMap.put("unsigned long long int", UnsignedLongLongDataType.dataType);

		cPrimitiveNameMap.put("float", FloatDataType.dataType);
		cPrimitiveNameMap.put("double", DoubleDataType.dataType);
		cPrimitiveNameMap.put("long double", LongDoubleDataType.dataType);
	}

	private static final Pattern DATATYPE_CONFLICT_PATTERN =
		Pattern.compile(Pattern.quote(DataType.CONFLICT_SUFFIX) + "_?[0-9]*");

	public static Collection<DataType> getContainedDataTypes(DataType rootDataType) {
		HashMap<String, DataType> dataTypeMap = new HashMap<>();
		Queue<DataType> unprocessedDataTypes = new LinkedList<>();
		dataTypeMap.put(rootDataType.getPathName(), rootDataType);
		unprocessedDataTypes.add(rootDataType);

		while (!unprocessedDataTypes.isEmpty()) {
			DataType dataType = unprocessedDataTypes.remove();
			List<DataType> directContainedDatatypes = getDirectContainedDatatypes(dataType);
			for (DataType containedDataType : directContainedDatatypes) {
				String path = containedDataType.getPathName();
				if (!dataTypeMap.containsKey(path)) {
					dataTypeMap.put(path, containedDataType);
					unprocessedDataTypes.add(containedDataType);
				}
			}
		}
		return dataTypeMap.values();
	}

	private static List<DataType> getDirectContainedDatatypes(DataType dt) {
		List<DataType> list = new ArrayList<>();
		if (dt instanceof Array) {
			Array array = (Array) dt;
			list.add(array.getDataType());
		}
		else if (dt instanceof Pointer) {
			Pointer ptr = (Pointer) dt;
			DataType ptrDt = ptr.getDataType();
			if (ptrDt != null) {
				list.add(ptrDt);
			}
		}
		else if (dt instanceof Composite) {
			Composite composite = (Composite) dt;
			int n = composite.getNumComponents();
			for (int i = 0; i < n; i++) {
				DataTypeComponent component = composite.getComponent(i);
				list.add(component.getDataType());
			}
		}
		else if (dt instanceof TypeDef) {
			TypeDef typedef = (TypeDef) dt;
			list.add(typedef.getDataType());
		}
		else if (dt instanceof Enum) {
			// no-op; prevents assert exception below
		}
		else if (dt instanceof FunctionDefinition) {
			FunctionDefinition funDef = (FunctionDefinition) dt;
			list.add(funDef.getReturnType());
			ParameterDefinition[] arguments = funDef.getArguments();
			for (ParameterDefinition parameter : arguments) {
				list.add(parameter.getDataType());
			}
		}
		else if (dt instanceof BuiltInDataType) {
			// no-op; prevents assert exception below
		}
		else if (dt instanceof BitFieldDataType) {
			BitFieldDataType bitFieldDt = (BitFieldDataType) dt;
			list.add(bitFieldDt.getBaseDataType());
		}
		else if (dt instanceof MissingBuiltInDataType) {
			// no-op; prevents assert exception below
		}
		else if (dt.equals(DataType.DEFAULT)) {
			// no-op; prevents assert exception below
		}
		else {
			throw new AssertException("Unknown data Type:" + dt.getDisplayName());
		}
		return list;
	}

	/**
	 * Check to see if the second data type is the same as the first data type or is part of it.
	 * <br>
	 * Note: pointers to the second data type are references and therefore are not considered to be
	 * part of the first and won't cause true to be returned. If you pass a pointer to this method
	 * for the first or second parameter, it will return false.
	 * 
	 * @param firstDataType the data type whose components or base type should be checked to see if
	 *            the second data type is part of it.
	 * @param secondDataType the data type to be checked for in the first data type.
	 * @return true if the second data type is the first data type or is part of it.
	 */
	public static boolean isSecondPartOfFirst(DataType firstDataType, DataType secondDataType) {
		if (firstDataType instanceof Pointer || secondDataType instanceof Pointer) {
			return false;
		}
		if (firstDataType.equals(secondDataType)) {
			return true;
		}
		if (firstDataType instanceof Array) {
			DataType elementDataType = ((Array) firstDataType).getDataType();
			return isSecondPartOfFirst(elementDataType, secondDataType);
		}
		if (firstDataType instanceof TypeDef) {
			DataType innerDataType = ((TypeDef) firstDataType).getDataType();
			return isSecondPartOfFirst(innerDataType, secondDataType);
		}
		if (firstDataType instanceof Composite) {
			Composite compositeDataType = (Composite) firstDataType;
			for (DataTypeComponent dtc : compositeDataType.getDefinedComponents()) {
				DataType dataTypeToCheck = dtc.getDataType();
				if (isSecondPartOfFirst(dataTypeToCheck, secondDataType)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Returns true if the two dataTypes have the same sourceArchive and the same UniversalID
	 * 
	 * @param dataType1 first data type
	 * @param dataType2 second data type
	 * @return true if types correspond to the same type from a source archive
	 */
	public static boolean isSameDataType(DataType dataType1, DataType dataType2) {
		UniversalID id1 = dataType1.getUniversalID();
		UniversalID id2 = dataType2.getUniversalID();
		if (id1 == null || id2 == null) {
			return false;
		}
		if (!id1.equals(id2)) {
			return false;
		}
		// Same universal id, but to be sure make sure the source archives are the same.
		SourceArchive sourceArchive1 = dataType1.getSourceArchive();
		SourceArchive sourceArchive2 = dataType2.getSourceArchive();
		if (sourceArchive1 == null || sourceArchive2 == null) {
			return false;
		}
		return sourceArchive1.getSourceArchiveID().equals(sourceArchive2.getSourceArchiveID());
	}

	/**
	 * Returns true if the two dataTypes have the same sourceArchive and the same UniversalID OR are
	 * equivalent
	 * 
	 * @param dataType1 first data type (if invoked by DB object or manager, this argument must
	 *            correspond to the DataTypeDB).
	 * @param dataType2 second data type
	 * @return true if types correspond to the same type from a source archive or they are
	 *         equivelent, otherwise false
	 */
	public static boolean isSameOrEquivalentDataType(DataType dataType1, DataType dataType2) {
		// if they contain datatypes that have same ids, then they represent the same dataType
		if (isSameDataType(dataType1, dataType2)) {
			return true;
		}
		// otherwise, check if they are equivalent
		return dataType1.isEquivalent(dataType2);
	}

	/**
	 * Get the name of a data type with all conflict naming patterns removed.
	 * 
	 * @param dataType data type
	 * @param includeCategoryPath if true the category path will be included with its
	 * @return name with without conflict patterns
	 */
	public static String getNameWithoutConflict(DataType dataType, boolean includeCategoryPath) {
		String name = includeCategoryPath ? dataType.getPathName() : dataType.getName();
		return DATATYPE_CONFLICT_PATTERN.matcher(name).replaceAll("");
	}

	/**
	 * Compares two data type name strings to determine if they are equivalent names, ignoring
	 * conflict patterns present.
	 * 
	 * @param name1 the first name
	 * @param name2 the second name
	 * @return true if the names are equivalent when conflict suffixes are ignored.
	 */
	public static boolean equalsIgnoreConflict(String name1, String name2) {
		name1 = DATATYPE_CONFLICT_PATTERN.matcher(name1).replaceAll("");
		name2 = DATATYPE_CONFLICT_PATTERN.matcher(name2).replaceAll("");
		return name1.equals(name2);
	}

	/**
	 * Get the base data type for the specified data type stripping away pointers and arrays only. A
	 * null will be returned for a default pointer.
	 *
	 * @param dt the data type whose base data type is to be determined.
	 * @return the base data type.
	 */
	public static DataType getBaseDataType(DataType dt) {
		DataType baseDataType = dt;
		while ((baseDataType instanceof Pointer) || (baseDataType instanceof Array)) {
			if (baseDataType instanceof Pointer) {
				baseDataType = ((Pointer) baseDataType).getDataType();
			}
			else if (baseDataType instanceof Array) {
				baseDataType = ((Array) baseDataType).getDataType();
			}
		}
		return baseDataType;
	}

	public static DataType getArrayBaseDataType(Array arrayDt) {
		DataType dataType = arrayDt.getDataType();
		if (dataType instanceof Array) {
			return getArrayBaseDataType((Array) dataType);
		}
		return dataType;
	}

	private static int getArrayBaseElementLength(Array arrayDt) {
		DataType dataType = arrayDt.getDataType();
		if (dataType instanceof Array) {
			return getArrayBaseElementLength((Array) dataType);
		}
		return arrayDt.getElementLength();
	}

	private static String getArrayElementLengthForDynamic(Array arrayDt) {
		if (getArrayBaseDataType(arrayDt).getLength() <= 0) {
			return " {" + getArrayBaseElementLength(arrayDt) + "} ";
		}
		return "";
	}

	private static String getArrayDimensions(Array arrayDt) {
		String dimensionString = "[" + arrayDt.getNumElements() + "]";
		DataType dataType = arrayDt.getDataType();
		if (dataType instanceof Array) {
			dimensionString += getArrayDimensions((Array) dataType);
		}
		return dimensionString;
	}

	public static String getName(Array arrayDt, boolean showBaseSizeForDynamics) {
		StringBuilder buf = new StringBuilder();
		buf.append(getArrayBaseDataType(arrayDt).getName());
		if (showBaseSizeForDynamics) {
			buf.append(getArrayElementLengthForDynamic(arrayDt));
		}
		buf.append(getArrayDimensions(arrayDt));
		return buf.toString();
	}

	public static String getDisplayName(Array arrayDt, boolean showBaseSizeForDynamics) {
		StringBuilder buf = new StringBuilder();
		buf.append(getArrayBaseDataType(arrayDt).getDisplayName());
		if (showBaseSizeForDynamics) {
			buf.append(getArrayElementLengthForDynamic(arrayDt));
		}
		buf.append(getArrayDimensions(arrayDt));
		return buf.toString();
	}

	public static String getMnemonic(Array arrayDt, boolean showBaseSizeForDynamics,
			Settings settings) {
		StringBuilder buf = new StringBuilder();
		buf.append(getArrayBaseDataType(arrayDt).getMnemonic(settings));
		if (showBaseSizeForDynamics) {
			buf.append(getArrayElementLengthForDynamic(arrayDt));
		}
		buf.append(getArrayDimensions(arrayDt));
		return buf.toString();
	}

	/**
	 * Create a data type category path derived from the specified namespace and rooted from the
	 * specified baseCategory
	 * 
	 * @param baseCategory category path from which to root the namespace-base path
	 * @param namespace the namespace
	 * @return namespace derived category path
	 */
	public static CategoryPath getDataTypeCategoryPath(CategoryPath baseCategory,
			Namespace namespace) {
		List<String> categoryPathParts = new ArrayList<>();
		for (Namespace ns : NamespaceUtils.getNamespaceParts(namespace)) {
			if (ns instanceof Library) {
				break; // assume the Library is a root and no other categories are above it
			}
			categoryPathParts.add(ns.getName());
		}
		return categoryPathParts.isEmpty()
				? baseCategory
				: new CategoryPath(baseCategory, categoryPathParts);
	}

	/**
	 * Attempt to find the data type whose dtName and specified namespace match a stored data type
	 * within the specified dataTypeManager. The best match will be returned. The namespace will be
	 * used in checking data type parent categories, however if no type corresponds to the namespace
	 * another type whose name matches may be returned.
	 * 
	 * @param dataTypeManager data type manager
	 * @param namespace namespace associated with dtName (null indicates no namespace constraint)
	 * @param dtName name of data type
	 * @param classConstraint optional data type interface constraint (e.g., Structure), or null
	 * @return best matching data type
	 */
	public static DataType findDataType(DataTypeManager dataTypeManager, Namespace namespace,
			String dtName, Class<? extends DataType> classConstraint) {
		return findDataType(dataTypeManager, dtName, classConstraint,
			categoryPath -> hasPreferredNamespaceCategory(categoryPath, namespace));
	}

	/**
	 * Attempt to find the data type whose dtNameWithNamespace match a stored data type within the
	 * specified dataTypeManager. The best match will be returned. The namespace will be used in
	 * checking data type parent categories, however if no type corresponds to the namespace another
	 * type whose name matches may be returned. NOTE: name parsing assumes :: delimiter and can be
	 * thrown off if name include template information which could contain namespaces.
	 * 
	 * @param dataTypeManager data type manager
	 * @param dtNameWithNamespace name of data type qualified with namespace (e.g.,
	 *            ns1::ns2::dtname)
	 * @param classConstraint optional data type interface constraint (e.g., Structure), or null
	 * @return best matching data type
	 */
	public static DataType findNamespaceQualifiedDataType(DataTypeManager dataTypeManager,
			String dtNameWithNamespace, Class<? extends DataType> classConstraint) {

		String[] splitName = dtNameWithNamespace.split(Namespace.DELIMITER);
		String dtName = splitName[splitName.length - 1];

		return findDataType(dataTypeManager, dtName, classConstraint,
			dataType -> hasPreferredNamespaceCategory(dataType, splitName));
	}

	/**
	 * Return the appropriate datatype for a given C primitive datatype name.
	 * 
	 * @param dataTypeName the datatype name (e.g. "unsigned int", "long long")
	 * @return the appropriate datatype for a given C primitive datatype name.
	 */
	public static DataType getCPrimitiveDataType(String dataTypeName) {
		// remove any excess spaces
		if (dataTypeName.contains(" ")) {
			dataTypeName = dataTypeName.trim().replaceAll("\\s+", " ");
		}
		dataTypeName = dataTypeName.toLowerCase();
		return cPrimitiveNameMap.get(dataTypeName);
	}

	private static boolean hasPreferredNamespaceCategory(DataType dataType,
			String[] splitDataTypeName) {
		// last element of split array is data type name and is ignored here
		if (splitDataTypeName.length == 1) {
			return true;
		}
		CategoryPath categoryPath = dataType.getCategoryPath();
		int index = splitDataTypeName.length - 2;
		while (index >= 0) {
			if (categoryPath.equals(CategoryPath.ROOT) ||
				!categoryPath.getName().equals(splitDataTypeName[index])) {
				return false;
			}
			categoryPath = categoryPath.getParent();
			--index;
		}
		return true;
	}

	private static boolean hasPreferredNamespaceCategory(DataType dataType, Namespace namespace) {
		if (namespace == null) {
			return true;
		}
		CategoryPath categoryPath = dataType.getCategoryPath();
		Namespace ns = namespace;
		while (!(ns instanceof GlobalNamespace) && !(ns instanceof Library)) {
			if (categoryPath.equals(CategoryPath.ROOT) ||
				!categoryPath.getName().equals(ns.getName())) {
				return false;
			}
			categoryPath = categoryPath.getParent();
			ns = ns.getParentNamespace();
		}
		return true;
	}

	/**
	 * <code>NamespaceMatcher</code> is used to check data type categoryPath for match against
	 * preferred namespace.
	 */
	private static interface NamespaceMatcher {
		boolean isNamespaceCategoryMatch(DataType dataType);
	}

	private static DataType findDataType(DataTypeManager dataTypeManager, String dtName,
			Class<? extends DataType> classConstraint, NamespaceMatcher preferredCategoryMatcher) {
		ArrayList<DataType> list = new ArrayList<>();
		dataTypeManager.findDataTypes(dtName, list);
		if (!list.isEmpty()) {
			//use the datatype that exists in the root category,
			//otherwise just pick the first one...
			DataType anyDt = null;
			DataType preferredDataType = null;
			for (DataType existingDT : list) {
				if (classConstraint != null &&
					!classConstraint.isAssignableFrom(existingDT.getClass())) {
					continue;
				}
				if (preferredCategoryMatcher == null) {
					if (existingDT.getCategoryPath().equals(CategoryPath.ROOT)) {
						return existingDT;
					}
				}
				if (preferredCategoryMatcher.isNamespaceCategoryMatch(existingDT)) {
					preferredDataType = existingDT;
				}
				// If all else fails return any matching name for backward compatibility
				anyDt = existingDT;
			}
			if (preferredDataType != null) {
				return preferredDataType;
			}
			return anyDt;
		}
		return null;
	}
}
