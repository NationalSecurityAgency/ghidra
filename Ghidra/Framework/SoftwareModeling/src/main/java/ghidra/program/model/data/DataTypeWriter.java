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
package ghidra.program.model.data;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * A class used to convert data types into ANSI-C.
 * 
 * The ANSI-C code should compile on most platforms.
 */
public class DataTypeWriter {

	// list of Ghidra built-in type names which correspond to C primitive types
	private static String[] INTEGRAL_TYPES = { "char", "short", "int", "long", "long long",
		"__int64", "float", "double", "long double", "void" };

	private static String[] INTEGRAL_MODIFIERS =
		{ "signed", "unsigned", "const", "static", "volatile", "mutable", };

	private static String EOL = System.getProperty("line.separator");

	private Set<DataType> resolved = new HashSet<>();
	private Map<String, DataType> resolvedTypeMap = new HashMap<>();
	private Set<Composite> deferredCompositeDeclarations = new HashSet<>();
	private ArrayDeque<DataType> deferredTypeFIFO = new ArrayDeque<>();
	private Set<DataType> deferredTypes = new HashSet<>();
	private int writerDepth = 0;
	private Writer writer;
	private DataTypeManager dtm;
	private DataOrganization dataOrganization;
	private AnnotationHandler annotator;
	private boolean cppStyleComments = false;

	/**
	 * Constructs a new instance of this class using the
	 * given writer. The default annotation handler is used.
	 * @param dtm data-type manager corresponding to target program or null
	 * for default
	 * @param writer the writer to use when writing data types
	 * @throws IOException 
	 */
	public DataTypeWriter(DataTypeManager dtm, Writer writer) throws IOException {
		this(dtm, writer, new DefaultAnnotationHandler());
	}

	/**
	 * Constructs a new instance of this class using the
	 * given writer. The default annotation handler is used.
	 * @param dtm data-type manager corresponding to target program or null
	 * for default
	 * @param writer the writer to use when writing data types
	 * @param cppStyleComments whether to use C++ style comments
	 * @throws IOException 
	 */
	public DataTypeWriter(DataTypeManager dtm, Writer writer, boolean cppStyleComments)
			throws IOException {
		this(dtm, writer, new DefaultAnnotationHandler(), cppStyleComments);
	}

	/**
	 * Constructs a new instance of this class using the
	 * given writer and annotation handler
	 * @param dtm data-type manager corresponding to target program or null
	 * for default
	 * @param writer the writer to use when writing data types
	 * @param annotator the annotation handler to use to annotate the data types
	 * @throws IOException 
	 */
	public DataTypeWriter(DataTypeManager dtm, Writer writer, AnnotationHandler annotator)
			throws IOException {
		this(dtm, writer, annotator, false);
	}

	/**
	 * Constructs a new instance of this class using the
	 * given writer and annotation handler
	 * @param dtm data-type manager corresponding to target program or null
	 * for default
	 * @param writer the writer to use when writing data types
	 * @param annotator the annotation handler to use to annotate the data types
	 * @param cppStyleComments whether to use C++ style comments
	 * @throws IOException 
	 */
	public DataTypeWriter(DataTypeManager dtm, Writer writer, AnnotationHandler annotator,
			boolean cppStyleComments) throws IOException {
		this.dtm = dtm;
		if (dtm != null) {
			dataOrganization = dtm.getDataOrganization();
		}
		if (dataOrganization == null) {
			dataOrganization = DataOrganizationImpl.getDefaultOrganization();
		}
		this.writer = writer;
		this.annotator = annotator;
		this.cppStyleComments = cppStyleComments;
		if (dtm != null) {
			writeBuiltInDeclarations(dtm);
		}
	}

	private String comment(String text) {
		if (text == null) {
			return "";
		}
		if (cppStyleComments) {
			return "// " + text;
		}
		return "/* " + text + " */";
	}

	/**
	 * Converts all data types in the data type manager into ANSI-C code. 
	 * @param dataTypeManager the manager containing the data types to write
	 * @param monitor the task monitor
	 * @throws IOException if an I/O error occurs when writing the data types to the specified writer
	 * @throws CancelledException 
	 */
	public void write(DataTypeManager dataTypeManager, TaskMonitor monitor)
			throws IOException, CancelledException {
		write(dataTypeManager.getRootCategory(), monitor);
	}

	/**
	 * Converts all data types in the category into ANSI-C code. 
	 * @param category the category containing the datatypes to write
	 * @param monitor the task monitor
	 * @throws IOException if an I/O error occurs when writing the data types to the specified writer
	 * @throws CancelledException 
	 */
	public void write(Category category, TaskMonitor monitor)
			throws IOException, CancelledException {
		DataType[] dataTypes = category.getDataTypes();
		write(dataTypes, monitor);

		Category[] subCategories = category.getCategories();
		for (Category subCategory : subCategories) {
			if (monitor.isCancelled()) {
				return;
			}
			write(subCategory, monitor);
		}
	}

	/**
	 * Converts all data types in the array into ANSI-C code. 
	 * @param dataTypes the data types to write
	 * @param monitor the task monitor
	 * @throws IOException if an I/O error occurs when writing the data types to the specified writer
	 * @throws CancelledException 
	 */
	public void write(DataType[] dataTypes, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.initialize(dataTypes.length);
		int cnt = 0;
		for (DataType dataType : dataTypes) {
			monitor.checkCanceled();
			write(dataType, monitor);
			monitor.setProgress(++cnt);
		}
	}

	/**
	 * Converts all data types in the list into ANSI-C code. 
	 * @param dataTypes the data types to write
	 * @param monitor the task monitor
	 * @throws IOException if an I/O error occurs when writing the data types to the specified writer
	 * @throws CancelledException 
	 */
	public void write(List<DataType> dataTypes, TaskMonitor monitor)
			throws IOException, CancelledException {
		write(dataTypes, monitor, true);
	}

	public void write(List<DataType> dataTypes, TaskMonitor monitor,
			boolean throwExceptionOnInvalidType) throws IOException, CancelledException {
		monitor.initialize(dataTypes.size());
		int cnt = 0;
		for (DataType dataType : dataTypes) {
			monitor.checkCanceled();
			write(dataType, monitor, throwExceptionOnInvalidType);
			monitor.setProgress(++cnt);
		}
	}

	private void deferWrite(DataType dt) {
		if (!resolved.contains(dt) && !deferredTypes.contains(dt)) {
			deferredTypes.add(dt);
			deferredTypeFIFO.addLast(dt);
		}
	}

	void write(DataType dt, TaskMonitor monitor) throws IOException, CancelledException {
		doWrite(dt, monitor, true);
	}

	void write(DataType dt, TaskMonitor monitor, boolean throwExceptionOnInvalidType)
			throws IOException, CancelledException {
		doWrite(dt, monitor, throwExceptionOnInvalidType);
	}

	/**
	 * Writes the data type as ANSI-C using the underlying writer.
	 * @param dt the data type to write as ANSI-C
	 * @param monitor
	 * @throws IOException
	 */
	private void doWrite(DataType dt, TaskMonitor monitor, boolean throwExceptionOnInvalidType)
			throws IOException, CancelledException {
		if (dt == null) {
			return;
		}
		if (dt instanceof FunctionDefinition) {
			return;
		}
		if (dt instanceof FactoryDataType) {
			IllegalArgumentException iae =
				new IllegalArgumentException("Factory data types may not be written");
			if (throwExceptionOnInvalidType) {
				throw iae;
			}
			Msg.error(this, "Factory data types may not be written - type: " + dt);
		}
		if (dt instanceof Pointer || dt instanceof Array || dt instanceof BitFieldDataType) {
			write(getBaseDataType(dt), monitor);
			return;
		}

		dt = dt.clone(dtm); // force resize/repack for target data organization

		if (resolved.contains(dt)) {
			return;
		}

		resolved.add(dt);

		DataType resolvedType = resolvedTypeMap.get(dt.getName());
		if (resolvedType != null) {
			if (resolvedType.isEquivalent(dt)) {
				return; // skip equivalent type with same name as a resolved type
			}
			if (dt instanceof TypeDef) {
				DataType baseType = ((TypeDef) dt).getBaseDataType();
				if (resolvedType instanceof Composite || resolvedType instanceof Enum) {
					if (baseType.isEquivalent(resolvedType)) {
						// auto-typedef already generated for Composite or Enum
						return;
					}
				}
			}
			writer.write(EOL);
			writer.write(comment("WARNING! conflicting data type names: " + dt.getPathName() +
				" - " + resolvedType.getPathName()));
			writer.write(EOL);
			writer.write(EOL);
			return;
		}

		resolvedTypeMap.put(dt.getName(), dt);

		++writerDepth;

		if (dt.equals(DataType.DEFAULT)) {
			writer.write("typedef unsigned char   " + DataType.DEFAULT.getName() + ";");
			writer.write(EOL);
			writer.write(EOL);
		}
		else if (dt instanceof Dynamic) {
			writeDynamicBuiltIn((Dynamic) dt, monitor);
		}
		else if (dt instanceof Structure) {
			Structure struct = (Structure) dt;
			writeCompositePreDeclaration(struct, monitor);
			deferredCompositeDeclarations.add(struct);
		}
		else if (dt instanceof Union) {
			Union union = (Union) dt;
			writeCompositePreDeclaration(union, monitor);
			deferredCompositeDeclarations.add(union);
		}
		else if (dt instanceof Enum) {
			writeEnum((Enum) dt, monitor);
		}
		else if (dt instanceof TypeDef) {
			writeTypeDef((TypeDef) dt, monitor);
		}
		else if (dt instanceof BuiltInDataType) {
			writeBuiltIn((BuiltInDataType) dt, monitor);
		}
		else if (dt instanceof BitFieldDataType) {
			// skip
		}
		else {
			writer.write(EOL);
			writer.write(EOL);
			writer.write(comment("Unable to write datatype. Type unrecognized: " + dt.getClass()));
			writer.write(EOL);
			writer.write(EOL);
		}

		if (writerDepth == 1) {
			writeDeferredDeclarations(monitor);
		}
		--writerDepth;
	}

	private void writeDeferredDeclarations(TaskMonitor monitor)
			throws IOException, CancelledException {
		while (!deferredTypes.isEmpty()) {
			DataType dt = deferredTypeFIFO.removeFirst();
			deferredTypes.remove(dt);
			write(dt, monitor);
		}
		writeDeferredCompositeDeclarations(monitor);
		deferredCompositeDeclarations.clear();
	}

	private DataType getBaseArrayTypedefType(DataType dt) {
		while (dt != null) {
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}
			else if (dt instanceof Array) {
				dt = ((Array) dt).getDataType();
			}
			else {
				break;
			}
		}
		return dt;
	}

	private boolean containsComposite(Composite container, Composite contained) {
		for (DataTypeComponent component : container.getDefinedComponents()) {
			DataType dt = getBaseArrayTypedefType(component.getDataType());
			if (dt instanceof Composite && dt.getName().equals(contained.getName()) &&
				dt.isEquivalent(contained)) {
				return true;
			}
		}
		return false;
	}

	private void writeDeferredCompositeDeclarations(TaskMonitor monitor)
			throws IOException, CancelledException {
		int cnt = deferredCompositeDeclarations.size();
		if (cnt == 0) {
			return;
		}

		LinkedList<Composite> list = new LinkedList<>(deferredCompositeDeclarations);
		if (list.size() > 1) {
			// Establish dependency ordering
			int sortChange = 1;
			while (sortChange != 0) {
				sortChange = 0;
				for (int i = cnt - 1; i > 0; i--) {
					if (resortComposites(list, i)) {
						++sortChange;
					}
				}
			}
		}

		for (Composite composite : list) {
			writeCompositeBody(composite, monitor);
		}
	}

	private boolean resortComposites(List<Composite> list, int index) {
		int listSize = list.size();
		if (listSize <= 0) {
			return false;
		}
		Composite composite = list.get(index);
		for (int i = 0; i < index; i++) {
			Composite other = list.get(i);
			if (containsComposite(other, composite)) {
				list.remove(index);
				list.add(i, composite);
				composite = null;
				return true;
			}
		}
		return false;
	}

	private String getDynamicComponentString(Dynamic dynamicType, String fieldName, int length) {
		if (dynamicType.canSpecifyLength()) {
			DataType replacementBaseType = dynamicType.getReplacementBaseType();
			if (replacementBaseType != null) {
				replacementBaseType = replacementBaseType.clone(dtm);
				int elementLen = replacementBaseType.getLength();
				if (elementLen <= 0) {
					Msg.error(this,
						dynamicType.getClass().getSimpleName() +
							" returned bad replacementBaseType: " +
							replacementBaseType.getClass().getSimpleName());
				}
				else {
					int elementCnt = (length + elementLen - 1) / elementLen;
					return replacementBaseType.getDisplayName() + " " + fieldName + "[" +
						elementCnt + "]";
				}
			}
		}
		return null;
	}

	private void writeCompositePreDeclaration(Composite composite, TaskMonitor monitor)
			throws IOException, CancelledException {

		String compositeType = composite instanceof Structure ? "struct" : "union";

		// output original name as a typedef
		writer.write("typedef " + compositeType + " " + composite.getDisplayName() + " " +
			composite.getDisplayName() + ", *P" + composite.getDisplayName() + ";");
		writer.write(EOL);
		writer.write(EOL);

		for (DataTypeComponent component : composite.getComponents()) {
			if (monitor.isCancelled()) {
				break;
			}
			// force resolution of field datatype
			DataType componentType = component.getDataType();
			deferWrite(componentType);

			// TODO the return value of this is not used--delete?
			getTypeDeclaration(null, componentType, component.getLength(), false, true, monitor);
		}

		if (composite instanceof Structure) {
			Structure s = (Structure) composite;
			if (s.hasFlexibleArrayComponent()) {
				DataType componentType = s.getFlexibleArrayComponent().getDataType();
				deferWrite(componentType);
			}
		}
	}

	private void writeCompositeBody(Composite composite, TaskMonitor monitor)
			throws IOException, CancelledException {

		String compositeType = composite instanceof Structure ? "struct" : "union";

		StringBuffer sb = new StringBuffer();
		sb.append(compositeType + " " + composite.getDisplayName() + " {");

		String descrip = composite.getDescription();
		if (descrip != null && descrip.length() > 0) {
			sb.append(" " + comment(descrip));
		}
		sb.append(EOL);

		for (DataTypeComponent component : composite.getComponents()) {
			monitor.checkCanceled();
			writeComponent(component, composite, sb, monitor);
		}

		if (composite instanceof Structure) {
			Structure s = (Structure) composite;
			if (s.hasFlexibleArrayComponent()) {
				writeComponent(s.getFlexibleArrayComponent(), composite, sb, monitor);
			}
		}

		sb.append(annotator.getSuffix(composite, null));
		sb.append("};");

		writer.write(sb.toString());
		writer.write(EOL);
		writer.write(EOL);
	}

	private void writeComponent(DataTypeComponent component, Composite composite, StringBuffer sb,
			TaskMonitor monitor) throws IOException, CancelledException {
		sb.append("    ");
		sb.append(annotator.getPrefix(composite, component));

		String fieldName = component.getFieldName();
		if (fieldName == null || fieldName.length() == 0) {
			fieldName = component.getDefaultFieldName();
		}

		DataType componentDataType = component.getDataType();

		sb.append(getTypeDeclaration(fieldName, componentDataType, component.getLength(),
			component.isFlexibleArrayComponent(), false, monitor));

		sb.append(";");
		sb.append(annotator.getSuffix(composite, component));

		String comment = component.getComment();
		if (comment != null && comment.length() > 0) {
			sb.append(" " + comment(comment));
		}
		sb.append(EOL);
	}

	private String getTypeDeclaration(String name, DataType dataType, int instanceLength,
			boolean isFlexArray, boolean writeEnabled, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (name == null) {
			name = "";
		}

		StringBuffer sb = new StringBuffer();
		String componentString = null;
		if (dataType instanceof Dynamic) {
			componentString = getDynamicComponentString((Dynamic) dataType, name, instanceLength);
			if (componentString != null) {
				sb.append(componentString);
			}
			else {
				sb.append(comment(
					"ignoring dynamic datatype inside composite: " + dataType.getDisplayName()));
				sb.append(EOL);
			}
		}

		if (componentString == null) {

			if (dataType instanceof BitFieldDataType) {
				BitFieldDataType bfDt = (BitFieldDataType) dataType;
				name += ":" + bfDt.getDeclaredBitSize();
				dataType = bfDt.getBaseDataType();
			}
			else if (dataType instanceof Array) {
				Array array = (Array) dataType;
				name += getArrayDimensions(array);
				dataType = getArrayBaseType(array);
			}

			DataType baseDataType = getBaseDataType(dataType);
			if (baseDataType instanceof FunctionDefinition) {
				componentString = getFunctionPointerString((FunctionDefinition) baseDataType, name,
					dataType, writeEnabled, monitor);
			}
			else {
				componentString = getDataTypePrefix(dataType) + dataType.getDisplayName();
				if (isFlexArray) {
					componentString += "[0]";
				}
				if (name.length() != 0) {
					componentString += " " + name;
				}
			}
			sb.append(componentString);
		}
		return sb.toString();
	}

	private String getDataTypePrefix(DataType dataType) {
		dataType = getBaseDataType(dataType);
		if (dataType instanceof Structure) {
			return "struct ";
		}
		else if (dataType instanceof Union) {
			return "union ";
		}
		else if (dataType instanceof Enum) {
			return "enum ";
		}
		return "";
	}

	private void writeEnum(Enum enumm, TaskMonitor monitor) throws IOException {

		String enumName = enumm.getDisplayName();
		if (enumName.startsWith("define_") && enumName.length() > 7 && enumm.getCount() == 1 &&
			enumm.getLength() == 8) {
			long val = enumm.getValues()[0];
			writer.append("#define " + enumName.substring(7) + " " + Long.toString(val));
			writer.write(EOL);
			writer.write(EOL);
			return;
		}

		writer.write("typedef enum " + enumName + " " + "{");
		String descrip = enumm.getDescription();
		if (descrip != null && descrip.length() != 0) {
			writer.write(" " + comment(descrip));
		}
		writer.write(EOL);
		String[] names = enumm.getNames();
		for (int j = 0; j < names.length; j++) {
			writer.write("    ");
			writer.write(annotator.getPrefix(enumm, names[j]));
			writer.write(names[j]);
			writer.write("=");
			writer.write(Long.toString(enumm.getValue(names[j])));
			writer.write(annotator.getSuffix(enumm, names[j]));
			if (j < names.length - 1) {
				writer.write(",");
			}
			writer.write(EOL);
		}
		writer.write("}" + " " + enumName + ";");
		writer.write(EOL);
		writer.write(EOL);
	}

	/**
	 * Typedef Format: typedef <TYPE_DEF_NAME> <BASE_TYPE_NAME>
	 * @throws CancelledException 
	 */
	private void writeTypeDef(TypeDef typeDef, TaskMonitor monitor)
			throws IOException, CancelledException {
		String typedefName = typeDef.getDisplayName();
		DataType dataType = typeDef.getDataType();
		String dataTypeName = dataType.getDisplayName();
		if (isIntegral(typedefName, dataTypeName)) {
			return;
		}

		DataType baseType = typeDef.getBaseDataType();
		try {
			if (baseType instanceof Composite || baseType instanceof Enum) {
				// auto-typedef generated with composite and enum
				if (typedefName.equals(baseType.getName())) {
					resolvedTypeMap.remove(typedefName);
					return;
				}
			}
			// TODO: A comment explaining the special 'P' case would be helpful!!  Smells like fish.
			else if (baseType instanceof Pointer && typedefName.startsWith("P")) {
				DataType dt = ((Pointer) baseType).getDataType();
				if (dt instanceof TypeDef) {
					dt = ((TypeDef) dt).getBaseDataType();
				}
				if (dt instanceof Composite && dt.getName().equals(typedefName.substring(1))) {
					// auto-pointer-typedef generated with composite
					resolvedTypeMap.remove(typedefName);
					return;
				}
			}
		}
		finally {
			write(dataType, monitor);
		}

		if (baseType instanceof Array && getBaseArrayTypedefType(baseType) instanceof Composite) {
			writeDeferredDeclarations(monitor);
		}

		String typedefString = getTypeDeclaration(typedefName, dataType, -1, false, true, monitor);

		writer.write("typedef " + typedefString + ";");
		writer.write(EOL);
		writer.write(EOL);
	}

	private boolean isIntegral(String typedefName, String basetypeName) {
		for (String type : INTEGRAL_TYPES) {
			if (typedefName.equals(type)) {
				return true;
			}
		}

		boolean endsWithIntegralType = false;
		for (String type : INTEGRAL_TYPES) {
			if (typedefName.endsWith(" " + type)) {
				endsWithIntegralType = true;
				break;
			}
		}
		boolean containsIntegralModifier = false;
		for (String modifier : INTEGRAL_MODIFIERS) {
			if (typedefName.indexOf(modifier + " ") >= 0 ||
				typedefName.indexOf(" " + modifier) >= 0) {
				return true;
			}
		}

		if (endsWithIntegralType && containsIntegralModifier) {
			return true;
		}

		if (typedefName.endsWith(" " + basetypeName)) {
			return containsIntegralModifier;
		}

		return false;
	}

	private void writeDynamicBuiltIn(Dynamic dt, TaskMonitor monitor)
			throws IOException, CancelledException {
		DataType baseDt = dt.getReplacementBaseType();
		if (baseDt != null) {
			write(baseDt, monitor);
		}
	}

	private void writeBuiltIn(BuiltInDataType dt, TaskMonitor monitor) throws IOException {
		String declaration = dt.getCTypeDeclaration(dataOrganization);
		if (declaration != null) {
			writer.write(declaration);
			writer.write(EOL);
		}
	}

	/**
	 * Write all built-in data types declarations into ANSI-C code.
	 * Those types whose name matches the corresponding primitive C-type.
	 * are not included.
	 * @throws IOException if an I/O error occurs when writing the data types to the specified writer
	 * @throws CancelledException 
	 */
	private void writeBuiltInDeclarations(DataTypeManager manager) throws IOException {

		try {
			write(DataType.DEFAULT, TaskMonitorAdapter.DUMMY_MONITOR);

			SourceArchive builtInArchive =
				manager.getSourceArchive(DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID);
			if (builtInArchive == null) {
				return;
			}

			for (DataType dt : manager.getDataTypes(builtInArchive)) {
				if ((dt instanceof Pointer) || (dt instanceof FactoryDataType) ||
					(dt instanceof Dynamic)) {
					continue;
				}
				write(dt, TaskMonitorAdapter.DUMMY_MONITOR);
			}
		}
		catch (CancelledException e) {
			// ignore - should never occur with dummy monitor
		}

		writer.flush();
	}

	private static String getArrayDimensions(Array arrayDt) {
		String dimensionString = "[" + arrayDt.getNumElements() + "]";
		DataType dataType = arrayDt.getDataType();
		if (dataType instanceof Array) {
			dimensionString += getArrayDimensions((Array) dataType);
		}
		return dimensionString;
	}

	private DataType getBaseDataType(DataType dt) {
		while (dt != null) {
			if (dt instanceof Array) {
				Array array = (Array) dt;
				dt = array.getDataType();
			}
			else if (dt instanceof Pointer) {
				Pointer pointer = (Pointer) dt;
				dt = pointer.getDataType();
			}
			else if (dt instanceof BitFieldDataType) {
				BitFieldDataType bitfieldDt = (BitFieldDataType) dt;
				dt = bitfieldDt.getBaseDataType();
			}
			else {
				break;
			}
		}
		return dt;
	}

	private DataType getArrayBaseType(Array arrayDt) {
		DataType dataType = arrayDt.getDataType();
		while (dataType instanceof Array) {
			dataType = ((Array) dataType).getDataType();
		}
		return dataType;
	}

	private DataType getPointerBaseDataType(Pointer p) {
		DataType dt = p.getDataType();
		while (dt instanceof Pointer) {
			dt = ((Pointer) dt).getDataType();
		}
		return dt;
	}

	private int getPointerDepth(Pointer p) {
		int depth = 1;
		for (DataType dt = p.getDataType(); dt instanceof Pointer; dt =
			((Pointer) dt).getDataType()) {
			++depth;
		}
		return depth;
	}

	private String getFunctionPointerString(FunctionDefinition fd, String name,
			DataType functionPointerArrayType, boolean writeEnabled, TaskMonitor monitor)
			throws IOException, CancelledException {

		DataType originalType = functionPointerArrayType;

		StringBuilder sb = new StringBuilder();

		DataType returnType = fd.getReturnType();
		if (writeEnabled) {
			write(returnType, monitor);
		}

		sb.append("(");
		String arrayDecorations = "";
		if (functionPointerArrayType instanceof Array) {
			Array a = (Array) functionPointerArrayType;
			functionPointerArrayType = getArrayBaseType(a);
			arrayDecorations = getArrayDimensions(a);
		}
		if (functionPointerArrayType instanceof Pointer) {
			Pointer p = (Pointer) functionPointerArrayType;
			for (int i = 0; i < getPointerDepth(p); i++) {
				sb.append('*');
			}
			if (name != null) {
				sb.append(' ');
			}
			functionPointerArrayType = getPointerBaseDataType(p);
		}
		if (!(functionPointerArrayType instanceof FunctionDefinition)) {
			writer.append(
				comment("Attempting output of invalid function pointer type declaration: " +
					originalType.getDisplayName()));
		}
		if (name != null) {
			sb.append(name);
		}
		if (arrayDecorations.length() != 0) {
			sb.append(arrayDecorations);
		}
		sb.append(")");
		sb.append(getParameterListString(fd, false, writeEnabled, monitor));

		DataType baseReturnType = getBaseDataType(returnType);
		if (baseReturnType instanceof FunctionDefinition) {
			// nest with function return type
			return getFunctionPointerString((FunctionDefinition) baseReturnType, sb.toString(),
				returnType, writeEnabled, monitor);
		}
		return returnType.getDisplayName() + " " + sb.toString();
	}

	private String getParameterListString(FunctionDefinition fd, boolean includeParamNames,
			boolean writeEnabled, TaskMonitor monitor) throws IOException, CancelledException {
		StringBuilder buf = new StringBuilder();
		buf.append("(");
		boolean hasVarArgs = fd.hasVarArgs();
		ParameterDefinition[] parameters = fd.getArguments();
		int n = parameters.length;
		for (int i = 0; i < n; i++) {
			ParameterDefinition param = parameters[i];
			String paramName = includeParamNames ? param.getName() : null;

			DataType dataType = param.getDataType();
			if (writeEnabled) {
				write(dataType, monitor);
			}
			String argument = getTypeDeclaration(paramName, dataType, param.getLength(), false,
				writeEnabled, monitor);

			buf.append(argument);

			if ((i < (n - 1)) || hasVarArgs) {
				buf.append(", ");
			}
		}
		if (hasVarArgs) {
			buf.append(ghidra.program.model.listing.FunctionSignature.VAR_ARGS_DISPLAY_STRING);
		}
		if ((n == 0) && (!hasVarArgs)) { // If no parameters
			buf.append(DataType.VOID.getName()); // Print "void" keyword
		}
		buf.append(")");
		return buf.toString();
	}
}
