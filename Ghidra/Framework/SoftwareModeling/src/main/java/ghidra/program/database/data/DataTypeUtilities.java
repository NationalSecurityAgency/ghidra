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
import ghidra.app.util.SymbolPathParser;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
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
	 * Returns true if two dataTypes have the same sourceArchive and the same UniversalID OR are
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
	 * Determine if two dataTypes are the same kind of datatype without considering naming or
	 * component makeup.  The use of Typedefs is ignored and stripped away for comparison.
	 * This method also ignores details about most built-in types, pointers and arrays 
	 * (e.g., number of elements or size).  Implementations of the following abstract classes
	 * will be treated as the same kind as another datatype which extends the same abstract
	 * class:
	 * <ul>
	 * <li>{@link AbstractIntegerDataType}</li> 
	 * <li>{@link AbstractFloatDataType}</li>
	 * <li>{@link AbstractStringDataType}</li>
	 * </ul>
	 *  Other uses of {@link BuiltInDataType} must match the specific implementation class. 
	 * @param dataType1 first data type
	 * @param dataType2 second data type
	 * @return true if the two dataTypes are the same basic kind else false
	 */
	public static boolean isSameKindDataType(DataType dataType1, DataType dataType2) {

		while (true) {
			if (dataType1 == dataType2) {
				return true;
			}

			// Ignore the use of typedefs - strip away
			if (dataType1 instanceof TypeDef td1) {
				dataType1 = td1.getBaseDataType();
			}
			if (dataType2 instanceof TypeDef td2) {
				dataType2 = td2.getBaseDataType();
			}

			if (dataType1 instanceof Pointer p1 && dataType2 instanceof Pointer p2) {
				dataType1 = p1.getDataType();
				dataType2 = p2.getDataType();
			}
			else if (dataType2 instanceof Array a1 && dataType2 instanceof Array a2) {
				dataType1 = a1.getDataType();
				dataType2 = a2.getDataType();
			}
			else if (dataType1 instanceof Enum) {
				return dataType2 instanceof Enum;
			}
			else if (dataType1 instanceof Structure) {
				return dataType2 instanceof Structure;
			}
			else if (dataType1 instanceof Union) {
				return dataType2 instanceof Union;
			}
			else if (dataType1 instanceof BuiltInDataType dt1) {
				return isSameKindBuiltInDataType(dt1, dataType2);
			}
			else {
				return false;
			}
		}
	}

	private static boolean isSameKindBuiltInDataType(BuiltInDataType dataType1,
			DataType dataType2) {
		if (dataType1 instanceof BuiltIn) {
			// Same kind if both types share a common BuiltIn implementation
			Class<?> baseClass = dataType1.getClass();
			Class<?> superClass;
			while ((superClass = baseClass.getSuperclass()) != BuiltIn.class) {
				baseClass = superClass;
			}
			return baseClass.isAssignableFrom(dataType2.getClass());
		}
		// Ensure built-in implementation class is the same
		return dataType1.getClass().equals(dataType2.getClass());
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
	 * Find the structure data type which corresponds to the specified class namespace
	 * within the specified data type manager.
	 * The structure must utilize a namespace-based category path, however,
	 * the match criteria can be fuzzy and relies primarily on the full class namespace.  
	 * A properly named class structure must reside within a category whose trailing 
	 * path either matches the class namespace or the class-parent's namespace.  
	 * Preference is given to it residing within the class-parent's namespace.
	 * @param dataTypeManager data type manager which should be searched.
	 * @param classNamespace class namespace
	 * @return existing structure which resides within matching category.
	 */
	public static Structure findExistingClassStruct(DataTypeManager dataTypeManager, GhidraClass classNamespace) {

		Structure dt = findPreferredDataType(dataTypeManager, classNamespace,
			classNamespace.getName(), Structure.class, true);
		if (dt != null) {
			return dt;
		}

		final String[] namespacePaths = getRelativeCategoryPaths(classNamespace);

		return findDataType(dataTypeManager, classNamespace.getName(), Structure.class,
			categoryPath -> getCategoryMatchType(categoryPath, namespacePaths, true));
	}

	/**
	 * Attempt to find the data type whose dtName and specified namespace match a stored data type
	 * within the specified dataTypeManager. The first match which satisfies the category path 
	 * requirement will be returned.  If a non-root namespace is specified the datatype's trailing 
	 * category path must match the specified namespace path.
	 * 
	 * @param dataTypeManager data type manager
	 * @param namespace namespace associated with dtName (null indicates no namespace constraint)
	 * @param dtName name of data type
	 * @param classConstraint optional data type interface constraint (e.g., Structure), or null
	 * @return best matching data type
	 */
	public static <T extends DataType> T findDataType(DataTypeManager dataTypeManager,
			Namespace namespace, String dtName, Class<T> classConstraint) {

		T dt =
			findPreferredDataType(dataTypeManager, namespace, dtName, classConstraint, false);
		if (dt != null) {
			return dt;
		}

		final String[] namespacePaths = getRelativeCategoryPaths(namespace);

		return findDataType(dataTypeManager, dtName, classConstraint,
			categoryPath -> getCategoryMatchType(categoryPath, namespacePaths, false));
	}

	/**
	 * Attempt to find the data type whose dtNameWithNamespace match a stored data type within the
	 * specified dataTypeManager. The namespace will be used in checking data type parent categories.  
	 * NOTE: name parsing assumes :: namespace delimiter which can be thrown off if name includes 
	 * template information which could contain namespaces (see {@link SymbolPathParser#parse(String)}).
	 * 
	 * @param dataTypeManager data type manager
	 * @param dtNameWithNamespace name of data type qualified with namespace (e.g.,
	 *            ns1::ns2::dtname)
	 * @param classConstraint optional data type interface constraint (e.g., Structure), or null
	 * @return best matching data type
	 */
	public static <T extends DataType> T findNamespaceQualifiedDataType(
			DataTypeManager dataTypeManager,
			String dtNameWithNamespace, Class<T> classConstraint) {

		List<String> pathList = SymbolPathParser.parse(dtNameWithNamespace);
		int nameIndex = pathList.size() - 1;
		String dtName = pathList.get(nameIndex);

		CategoryPath rootPath = getPreferredRootNamespaceCategoryPath(dataTypeManager);
		if (rootPath != null) {
			List<String> namespacePath = pathList.subList(0, nameIndex);
			T dt = getAssignableDataType(dataTypeManager, rootPath, namespacePath, dtName,
				classConstraint);
			if (dt != null) {
				return dt;
			}
		}

		// generate namespace path with / instead of :: separators
		StringBuilder buf = new StringBuilder();
		for (int i = 0; i < nameIndex; i++) {
			buf.append(CategoryPath.DELIMITER_STRING);
			buf.append(pathList.get(i));
		}
		final String namespacePath = buf.toString(); // root path will have empty string 

		return findDataType(dataTypeManager, dtName, classConstraint,
			categoryPath -> getCategoryMatchType(categoryPath, namespacePath));
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

	private static final int NAMESPACE_PATH_INDEX = 0;
	private static final int PARENT_NAMESPACE_PATH_INDEX = 1;

	/**
	 * Get relative/partial category paths which corresponds to a specified namespace.
	 * Any {@link Library} namespace will be ignored and treated like the global namespace 
	 * when generating a related category path. An empty string will be returned for the
	 * global namespace.
	 * @param namespace data type namespace
	 * @return partial two-element array with category path for namespace [NAMESPACE_PATH_INDEX] 
	 * and parent-namespace [PARENT_NAMESPACE_PATH_INDEX].
	 * A null is returned if namespace is null or the root/global namespace.
	 */
	private static String[] getRelativeCategoryPaths(Namespace namespace) {
		if (namespace == null || namespace.isGlobal() || namespace.isLibrary()) {
			return null;
		}
		String[] paths = new String[2];
		StringBuilder buf = new StringBuilder();
		for (String n : namespace.getParentNamespace().getPathList(true)) {
			buf.append(CategoryPath.DELIMITER_STRING);
			buf.append(CategoryPath.escapeString(n));
		}
		paths[PARENT_NAMESPACE_PATH_INDEX] = buf.toString();
		buf.append(CategoryPath.DELIMITER_STRING);
		buf.append(CategoryPath.escapeString(namespace.getName()));
		paths[NAMESPACE_PATH_INDEX] = buf.toString();
		return paths;
	}

	private enum CategoryMatchType {
		NONE, SECONDARY, PREFERRED;
	}

	/**
	 * Namespace category matcher.  Only those datatypes contained within a catgeory
	 * whose trailing category path matches the specified namespacePath will be considered
	 * a possible match.  If the namespacePath is empty array all category paths will 
	 * be considered a match with preference given to the root category.
	 * @param categoryPath datatype category path
	 * @param namespacePath namespace path
	 * @return {@link CategoryMatchType#PREFERRED} if namespace match found, {@link CategoryMatchType#SECONDARY}
	 * if no namespace constraint specified else {@link CategoryMatchType#NONE} if namespace constraint not 
	 * satisfied.
	 */
	private static CategoryMatchType getCategoryMatchType(CategoryPath categoryPath,
			String namespacePath) {
		if (namespacePath.length() == 0) {
			// root or unspecified namespace - prefer root category
			return categoryPath.isRoot() ? CategoryMatchType.PREFERRED : CategoryMatchType.SECONDARY;
		}
		String path = categoryPath.getPath();
		return path.endsWith(namespacePath) ? CategoryMatchType.PREFERRED : CategoryMatchType.NONE;
	}

	/**
	 * Namespace category matcher.  
	 * @param categoryPath datatype category path
	 * @param namespacePaths namespace paths constraint or null for no namespace.  This value should
	 * be obtained from the {@link #getRelativeCategoryPaths(Namespace)} method.
	 * @param parentNamespacePreferred if true matching on parent namespace is 
	 * enabled and preferred over match on actual namespace.  This is used for
	 * class structure searching.
	 * @return {@link CategoryMatchType#PREFERRED} is returned if parentNamespacePreferred is true 
	 * and category path matches on parent-namespace or parentNamespacePreferred is false
	 * and category path matches on namespace.  {@link CategoryMatchType#SECONDARY} is returned
	 * if parentNamespacePreferred is true and category path matches on namespace.  Otherwise
	 * {@link CategoryMatchType#NONE} is returned.
	 */
	private static CategoryMatchType getCategoryMatchType(CategoryPath categoryPath,
			String[] namespacePaths, boolean parentNamespacePreferred) {
		if (namespacePaths == null) {
			// root or unspecified namespace - prefer root category
			return categoryPath.isRoot() ? CategoryMatchType.PREFERRED : CategoryMatchType.SECONDARY;
		}

		String path = categoryPath.getPath();
		if (parentNamespacePreferred &&
			path.endsWith(namespacePaths[PARENT_NAMESPACE_PATH_INDEX])) {
			return CategoryMatchType.PREFERRED;
		}
		if (path.endsWith(namespacePaths[NAMESPACE_PATH_INDEX])) {
			return parentNamespacePreferred ? CategoryMatchType.SECONDARY
					: CategoryMatchType.PREFERRED;
		}
		return CategoryMatchType.NONE;
	}

	/**
	 * <code>NamespaceMatcher</code> is used to check data type categoryPath for match against
	 * preferred namespace.
	 */
	private static interface NamespaceMatcher {
		/**
		 * Score category path match.
		 * @param path category path
		 * @return path match type
		 */
		CategoryMatchType getMatchType(CategoryPath path);
	}

	private static CategoryPath getPreferredRootNamespaceCategoryPath(
			DataTypeManager dataTypeManager) {
		if (!(dataTypeManager instanceof ProgramBasedDataTypeManager)) {
			return null;
		}
		ProgramBasedDataTypeManager pdtm = (ProgramBasedDataTypeManager) dataTypeManager;
		Program p = pdtm.getProgram();
		return p.getPreferredRootNamespaceCategoryPath();
	}

	/**
	 * Get the specified datatype by full path and return only if its type corresponds to class
	 * constraint if specified.
	 * @param <T> A standard interface which extends {@link DataType} (e.g., {@link Structure}).
	 * @param dataTypeManager datatype manager to query
	 * @param rootPath root category path
	 * @param namespacePath an optional namespace path to be checked under rootPath.  
	 * If null or empty the rootPath will be checked for dtName.
	 * @param dtName datatype name
	 * @param classConstraint datatype class constraint (optional, may be null)
	 * @return datatype which corresponds to specified path or null if not found
	 */
	private static <T extends DataType> T getAssignableDataType(DataTypeManager dataTypeManager,
			CategoryPath rootPath, List<String> namespacePath, String dtName,
			Class<? extends DataType> classConstraint) {

		Category category = dataTypeManager.getCategory(rootPath);
		if (category == null) {
			return null;
		}

		if (namespacePath == null || namespacePath.isEmpty()) {
			return getAssignableDataType(category, dtName, classConstraint);
		}

		CategoryPath categoryPath = new CategoryPath(rootPath, namespacePath);
		category = dataTypeManager.getCategory(categoryPath);
		if (category == null) {
			return null;
		}
		return getAssignableDataType(category, dtName, classConstraint);
	}

	/**
	 * Get the specified datatype by name and category and return only if its type 
	 * corresponds to an class constraint if specified.
	 * @param <T> A standard interface which extends {@link DataType} (e.g., {@link Structure}).
	 * @param category datatype category to query
	 * @param dtName datatype name
	 * @param classConstraint datatype class constraint (optional, may be null)
	 * @return datatype which corresponds to specified path or null if not found
	 */
	@SuppressWarnings("unchecked")
	private static <T extends DataType> T getAssignableDataType(Category category, String dtName,
			Class<? extends DataType> classConstraint) {
		DataType dt = category.getDataType(dtName);
		if (dt != null &&
			(classConstraint == null || classConstraint.isAssignableFrom(dt.getClass()))) {
			return (T) dt;
		}
		return null;
	}

	/**
	 * Perform a preferred category namespace qualified datatype search using
	 * category path supplied by {@link Program#getPreferredRootNamespaceCategoryPath()}.
	 * Any {@link Library} namespace will be ignored and treated like the global namespace 
	 * when generating a related category path.  This method only applies to 
	 * {@link ProgramBasedDataTypeManager} and will always return null for other 
	 * datatype managers.
	 * @param dataTypeManager datatype manager
	 * @param namespace namespace constraint or null for no namespace.
	 * @param dtName datatype name
	 * @param classConstraint type of datatype by its interface class (e.g., {@link Structure}).
	 * @param parentNamespacePreferred if true matching on parent namespace is 
	 * enabled and preferred over match on actual namespace.  This is relavent for
	 * class structure searching.
	 * @return preferred datatype match if found
	 */
	private static <T extends DataType> T findPreferredDataType(DataTypeManager dataTypeManager,
			Namespace namespace, String dtName, Class<T> classConstraint,
			boolean parentNamespacePreferred) {
		CategoryPath rootPath = getPreferredRootNamespaceCategoryPath(dataTypeManager);
		if (rootPath == null) {
			return null;
		}

		if (namespace == null || namespace.isGlobal() || namespace.isLibrary()) {
			return getAssignableDataType(dataTypeManager, rootPath, null, dtName, classConstraint);
		}

		if (parentNamespacePreferred) {
			T dt = getAssignableDataType(dataTypeManager, rootPath,
				namespace.getParentNamespace().getPathList(true), dtName, classConstraint);
			if (dt != null) {
				return dt;
			}
		}

		return getAssignableDataType(dataTypeManager, rootPath, namespace.getPathList(true), dtName,
			classConstraint);
	}

	/**
	 * Compare datatype category path lengths for sorting shortest path first.
	 * Tie-breaker based on path name sort.
	 * Rationale is to provide some deterministic datatype selection behavior and
	 * to allow duplicates within a hierarchical orgainzation to prefer the short
	 * path to reduce bad namespace matches.
	 */
	private static final Comparator<DataType> DATATYPE_CATEGORY_PATH_LENGTH_COMPARATOR =
		(DataType dt1, DataType dt2) -> {
			String catPath1 = dt1.getCategoryPath().getPath();
			String catPath2 = dt2.getCategoryPath().getPath();
			int cmp = catPath1.length() - catPath2.length();
			if (cmp == 0) {
				cmp = catPath1.compareTo(catPath2);
			}
			return cmp;
	};

	/**
	 * Perform a namespace qualified datatype search.  
	 * @param dataTypeManager datatype manager
	 * @param dtName datatype name
	 * @param classConstraint type of datatype by its interface class (e.g., {@link Structure}).
	 * @param categoryMatcher responsible for evaluating the category path
	 * for a possible match with a namespace constraint.  
	 * @return The first {@link CategoryMatchType#PREFERRED} match will be 
	 * returned if found.  If none are {@link CategoryMatchType#PREFERRED}, the first 
	 * {@link CategoryMatchType#SECONDARY} match will be returned.  Otherwise null is returned. 
	 */
	@SuppressWarnings("unchecked")
	private static <T extends DataType> T findDataType(DataTypeManager dataTypeManager,
			String dtName, Class<T> classConstraint, NamespaceMatcher categoryMatcher) {

		ArrayList<DataType> list = new ArrayList<>();
		dataTypeManager.findDataTypes(dtName, list);
		Collections.sort(list, DATATYPE_CATEGORY_PATH_LENGTH_COMPARATOR);
		if (!list.isEmpty()) {
			T secondaryMatch = null;
			for (DataType existingDT : list) {
				if (classConstraint != null &&
					!classConstraint.isAssignableFrom(existingDT.getClass())) {
					continue;
				}
				CategoryMatchType matchType =
					categoryMatcher.getMatchType(existingDT.getCategoryPath());
				if (matchType == CategoryMatchType.PREFERRED) {
					return (T) existingDT; // preferred match
				}
				else if (secondaryMatch == null && matchType == CategoryMatchType.SECONDARY) {
					secondaryMatch = (T) existingDT;
				}
			}
			return secondaryMatch;
		}
		return null;
	}
}
