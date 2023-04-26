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
package ghidra.program.model.data.ISF;

import java.io.IOException;
import java.io.Writer;
import java.lang.annotation.*;
import java.util.*;
import java.util.Map.Entry;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A class used to export data types and symbols as ISF JSON.
 *
 * The ISF JSON should be valid for Volatility is STRICT==true.
 */
public class IsfDataTypeWriter {

	private Map<DataType, IsfObject> resolved = new HashMap<>();
	private Map<String, DataType> resolvedTypeMap = new HashMap<>();
	private List<String> deferredKeys = new ArrayList<>();

	private Writer baseWriter;
	private JsonWriter writer;
	private Gson gson = new GsonBuilder().setPrettyPrinting().create();

	private DataTypeManager dtm;
	private DataOrganization dataOrganization;

	private JsonObject data = new JsonObject();
	private JsonObject metadata = new JsonObject();
	private JsonObject baseTypes = new JsonObject();
	private JsonObject userTypes = new JsonObject();
	private JsonObject enums = new JsonObject();
	private JsonObject symbols = new JsonObject();

	private List<Address> requestedAddresses = new ArrayList<>();
	private List<String> requestedSymbols = new ArrayList<>();
	private List<String> requestedTypes = new ArrayList<>();
	private List<DataType> requestedDataTypes = new ArrayList<>();
	private boolean skipSymbols = false;
	private boolean skipTypes = false;

	/**
	 * Constructs a new instance of this class using the given writer
	 * 
	 * @param dtm data-type manager corresponding to target program or null for default
	 * @param baseWriter the writer to use when writing data types
	 * @throws IOException if there is an exception writing the output
	 */
	public IsfDataTypeWriter(DataTypeManager dtm, Writer baseWriter) throws IOException {
		this.dtm = dtm;
		if (dtm != null) {
			dataOrganization = dtm.getDataOrganization();
		}
		if (dataOrganization == null) {
			dataOrganization = DataOrganizationImpl.getDefaultOrganization();
		}
		this.baseWriter = baseWriter;
		this.writer = new JsonWriter(baseWriter);
		writer.setIndent("  ");
		this.gson = new GsonBuilder()
				.addSerializationExclusionStrategy(strategy)
				.setPrettyPrinting()
				.create();
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public @interface Exclude {
		//EMPTY
	}

	// Am setting this as the default, but it's possible we may want more latitude in the future
	private boolean STRICT = true;

	// @Exclude used for properties that might be desirable for a non-STRICT implementation.
	ExclusionStrategy strategy = new ExclusionStrategy() {
		@Override
		public boolean shouldSkipClass(Class<?> clazz) {
			return false;
		}

		@Override
		public boolean shouldSkipField(FieldAttributes field) {
			return STRICT && field.getAnnotation(Exclude.class) != null;
		}
	};

	/**
	 * Exports all data types in the list as ISF JSON.
	 * 
	 * @param monitor the task monitor
	 * @return the resultant JSON object
	 * @throws IOException if there is an exception writing the output
	 * @throws CancelledException if the action is cancelled by the user
	 */
	public JsonObject getRootObject(TaskMonitor monitor)
			throws IOException, CancelledException {

		genMetadata();
		genTypes(monitor);
		genSymbols();
		genRoot();

		return data;
	}

	private void genRoot() {
		data.add("metadata", metadata);
		data.add("base_types", baseTypes);
		data.add("user_types", userTypes);
		data.add("enums", enums);
		// Would be nice to support this in the futere, but Volatility does not
		//data.add("typedefs", typedefs);
		data.add("symbols", symbols);
	}

	private void genMetadata() {
		String oskey = "UNKNOWN";
		if (dtm instanceof ProgramDataTypeManager) {
			ProgramDataTypeManager pgmDtm = (ProgramDataTypeManager) dtm;
			Program program = pgmDtm.getProgram();
			Map<String, String> metaData = program.getMetadata();

			JsonElement producer = gson.toJsonTree(new IsfProducer(program));
			JsonElement os = new JsonObject();
			oskey = metaData.get("Compiler ID");
			if (metaData.containsKey("PDB Loaded")) {
				os = gson.toJsonTree(new IsfWinOS(metaData));
			}
			else if (metaData.containsKey("Executable Format")) {
				if (metaData.get("Executable Format").contains("ELF")) {
					oskey = "linux";
					os = gson.toJsonTree(new IsfLinuxOS(gson, metaData));
				}
			}
			metadata.addProperty("format", "6.2.0");
			metadata.add("producer", producer);
			metadata.add(oskey, os);
		}
	}

	private void genSymbols() {
		if (!skipSymbols && dtm instanceof ProgramDataTypeManager) {
			ProgramDataTypeManager pgmDtm = (ProgramDataTypeManager) dtm;
			Program program = pgmDtm.getProgram();
			Address imageBase = program.getImageBase();
			SymbolTable symbolTable = program.getSymbolTable();
			ReferenceManager referenceManager = program.getReferenceManager();
			ReferenceIterator xrefs = referenceManager.getExternalReferences();
			Map<String, Symbol> linkages = new HashMap<>();
			for (Reference reference : xrefs) {
				Address fromAddress = reference.getFromAddress();
				Address toAddress = reference.getToAddress();
				Symbol fromSymbol = symbolTable.getPrimarySymbol(fromAddress);
				Symbol toSymbol = symbolTable.getPrimarySymbol(toAddress);
				if (fromSymbol != null) {
					linkages.put(toSymbol.getName(), fromSymbol);
				}
			}

			Map<String, JsonObject> map = new HashMap<>();
			if (requestedSymbols.isEmpty()) {
				if (requestedAddresses.isEmpty()) {
					SymbolIterator iterator = symbolTable.getSymbolIterator();
					while (iterator.hasNext()) {
						Symbol symbol = iterator.next();
						symbolToJson(imageBase, symbolTable, linkages, map, symbol);
					}
				}
				else {
					for (Address addr : requestedAddresses) {
						Symbol[] symsFromAddr =
							symbolTable.getSymbols(addr.add(imageBase.getOffset()));
						for (Symbol symbol : symsFromAddr) {
							symbolToJson(imageBase, symbolTable, linkages, map, symbol);
						}
					}
				}
			}
			else {
				for (String key : requestedSymbols) {
					SymbolIterator iter = symbolTable.getSymbols(key);
					while (iter.hasNext()) {
						Symbol symbol = iter.next();
						symbolToJson(imageBase, symbolTable, linkages, map, symbol);
					}
				}
			}
			for (Entry<String, JsonObject> entry : map.entrySet()) {
				symbols.add(entry.getKey(), entry.getValue());
			}
			for (Entry<String, JsonObject> entry : map.entrySet()) {
				if (entry.getKey().startsWith("_")) {
					String nu = entry.getKey().substring(1);
					if (symbols.get(nu) == null) {
						symbols.add(nu, entry.getValue());
					}
				}
			}
		}
	}

	private void genTypes(TaskMonitor monitor)
			throws CancelledException, IOException {
		if (skipTypes) {
			return;
		}
		Map<String, DataType> map = new HashMap<>();
		if (requestedDataTypes.isEmpty()) {
			dtm.getAllDataTypes(requestedDataTypes);
			baseTypes.add("pointer", getTree(new IsfTypedefPointer()));
			baseTypes.add("undefined", getTree(new IsfTypedefPointer()));
		}
		monitor.initialize(requestedDataTypes.size());
		for (DataType dataType : requestedDataTypes) {
			String key = dataType.getName();
			map.put(key, dataType);
		}

		List<String> keylist = new ArrayList<>(map.keySet());
		Collections.sort(keylist);
		processMap(map, keylist, monitor);

		if (!deferredKeys.isEmpty()) {
			Msg.warn(this, "Processing .conflict objects");
			List<String> defkeys = new ArrayList<>();
			defkeys.addAll(deferredKeys);
			processMap(map, defkeys, monitor);
		}
	}

	private void processMap(Map<String, DataType> map, List<String> keylist, TaskMonitor monitor)
			throws CancelledException, IOException {
		JsonObject obj = new JsonObject();
		int cnt = 0;
		for (String key : keylist) {
			DataType dataType = map.get(key);
			monitor.checkCancelled();
			if (key.contains(".conflict")) {
				continue;
			}
			obj = getObjectForDataType(dataType, monitor);
			if (obj == null) {
				continue;
			}
			if (dataType instanceof FunctionDefinition) {
				// Would be nice to support this in the futere, but Volatility does not
				//typedefs.add(dataType.getName(), obj);
			}
			else if (IsfUtilities.isBaseDataType(dataType)) {
				baseTypes.add(dataType.getName(), obj);
			}
			else if (dataType instanceof TypeDef) {
				DataType baseDataType = ((TypeDef) dataType).getBaseDataType();
				if (IsfUtilities.isBaseDataType(baseDataType)) {
					baseTypes.add(dataType.getName(), obj);
				}
				else if (baseDataType instanceof Enum) {
					enums.add(dataType.getName(), obj);
				}
				else {
					userTypes.add(dataType.getName(), obj);
				}
			}
			else if (dataType instanceof Enum) {
				enums.add(dataType.getName(), obj);
			}
			else if (dataType instanceof Composite) {
				userTypes.add(dataType.getName(), obj);
			}
			monitor.setProgress(++cnt);
		}
	}

	private void symbolToJson(Address imageBase, SymbolTable symbolTable,
			Map<String, Symbol> linkages,
			Map<String, JsonObject> map, Symbol symbol) {
		String key = symbol.getName();
		Address address = symbol.getAddress();
		JsonObject sym = map.containsKey(key) ? map.get(key) : new JsonObject();
		if (address.isExternalAddress()) {
			sym.addProperty("address", address.getOffset());
			if (linkages.containsKey(key)) {
				Symbol linkage = linkages.get(key);
				sym.addProperty("linkage_name", linkage.getName());
				sym.addProperty("address", linkage.getAddress().getOffset());
			}
		}
		else {
			sym.addProperty("address", address.subtract(imageBase));
		}
		map.put(symbol.getName(), sym);
		if (!symbol.isPrimary()) {
			Symbol primarySymbol = symbolTable.getPrimarySymbol(address);
			String primaryName = primarySymbol.getName();
			if (symbol.getName().contains(primaryName)) {
				sym.addProperty("linkage_name", symbol.getName());
				map.put(primaryName, sym);
			}
		}
	}

	public void write(JsonObject obj) {
		gson.toJson(obj, writer);
	}

	JsonObject getObjectForDataType(DataType dt, TaskMonitor monitor)
			throws IOException, CancelledException {
		IsfObject isf = getIsfObject(dt, monitor);
		if (isf != null) {
			JsonObject jobj = (JsonObject) getTree(isf);
			resolved.put(dt, isf);
			return jobj;
		}
		return null;
	}

	/**
	 * Writes the data type as ISF JSON using the underlying writer. For now, ignoring top-level
	 * bit-fields and function defs as unsupported by ISF. Typedefs really deserve their own
	 * category, but again unsupported.
	 * 
	 * @param dt the data type to write as ISF JSON
	 * @param monitor the task monitor
	 * @throws IOException if there is an exception writing the output
	 */
	private IsfObject getIsfObject(DataType dt, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (dt == null) {
			Msg.error(this, "Shouldn't get here - null datatype passed");
			return null;
		}
		if (dt instanceof FactoryDataType) {
			Msg.error(this, "Factory data types may not be written - type: " + dt);
		}
		if (dt instanceof Pointer || dt instanceof Array || dt instanceof BitFieldDataType) {
			IsfObject type = getObjectDataType(IsfUtilities.getBaseDataType(dt));
			IsfObject obj = new IsfTypedObject(dt, type);
			return obj;
		}

		dt = dt.clone(dtm); // force resize/repack for target data organization

		IsfObject res = resolve(dt);
		if (res != null) {
			return res;
		}

		if (dt instanceof Dynamic dynamic) {
			DataType rep = dynamic.getReplacementBaseType();
			return rep == null ? null : getIsfObject(rep, monitor);
		}
		else if (dt instanceof TypeDef typedef) {
			return getObjectTypeDef(typedef, monitor);
		}
		else if (dt instanceof Composite composite) {
			return new IsfComposite(composite, this, monitor);
		}
		else if (dt instanceof Enum enumm) {
			return new IsfEnum(enumm);
		}
		else if (dt instanceof BuiltInDataType builtin) {
			return new IsfBuiltIn(builtin);
		}
		else if (dt instanceof BitFieldDataType) {
			// skip - not hit
		}
		else if (dt instanceof FunctionDefinition) {  ///FAIL
			// skip - not hit
		}
		else if (dt.equals(DataType.DEFAULT)) {
			// skip - not hit
		}
		else {
			Msg.warn(this, "Unable to write datatype. Type unrecognized: " + dt.getClass());
		}

		return null;
	}

	private IsfObject resolve(DataType dt) {
		if (resolved.containsKey(dt)) {
			return resolved.get(dt);
		}

		DataType resolvedType = resolvedTypeMap.get(dt.getName());
		if (resolvedType != null) {
			if (resolvedType.isEquivalent(dt)) {
				return resolved.get(dt); // skip equivalent type with same name as a resolved type
			}
			if (dt instanceof TypeDef) {
				DataType baseType = ((TypeDef) dt).getBaseDataType();
				if (resolvedType instanceof Composite || resolvedType instanceof Enum) {
					if (baseType.isEquivalent(resolvedType)) {
						// auto-typedef already generated for Composite or Enum
						return resolved.get(dt);
					}
				}
			}
			Msg.warn(this, "WARNING! conflicting data type names: " + dt.getPathName() +
				" - " + resolvedType.getPathName());
			return resolved.get(dt);
		}

		resolvedTypeMap.put(dt.getName(), dt);
		return null;
	}

	private void clearResolve(String typedefName, DataType baseType) {
		if (baseType instanceof Composite || baseType instanceof Enum) {
			// auto-typedef generated with composite and enum
			if (typedefName.equals(baseType.getName())) {
				resolvedTypeMap.remove(typedefName);
				return;
			}
		}
		// Inherited from DataTypeWriter (logic lost to time): 
		//    A comment explaining the special 'P' case would be helpful!!  Smells like fish.
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

	public IsfObject getObjectTypeDeclaration(DataTypeComponent component) {

		DataType dataType = component.getDataType();
		if (dataType instanceof Dynamic dynamic) {
			if (dynamic.canSpecifyLength()) {
				DataType replacementBaseType = dynamic.getReplacementBaseType();
				if (replacementBaseType != null) {
					replacementBaseType = replacementBaseType.clone(dtm);
					IsfObject type = getObjectDataType(replacementBaseType);
					int elementLen = replacementBaseType.getLength();
					if (elementLen > 0) {
						int elementCnt = (component.getLength() + elementLen - 1) / elementLen;
						return new IsfDynamicComponent(dynamic, type, elementCnt);

					}
					Msg.error(this,
						dynamic.getClass().getSimpleName() +
							" returned bad replacementBaseType: " +
							replacementBaseType.getClass().getSimpleName());
				}
			}
			return null;
		}

		DataType baseDataType = IsfUtilities.getBaseDataType(dataType);
		if (baseDataType instanceof FunctionDefinition def) {
			return new IsfFunctionPointer(def, baseDataType);
		}
		return getObjectDataType(dataType, component.getOffset());
	}

	public IsfObject getObjectDataType(DataType dataType) {
		return getObjectDataType(dataType, -1);
	}

	private IsfObject getObjectDataType(DataType dataType, int componentOffset) {
		if (dataType == null) {
			return new IsfDataTypeNull();
		}
		DataType baseType = IsfUtilities.getBaseDataType(dataType);
		if (!dataType.equals(baseType)) {
			if (dataType instanceof Array arr) {
				IsfObject type = getObjectDataType(arr.getDataType());
				return new IsfDataTypeArray(arr, type);
			}
			if (dataType instanceof BitFieldDataType bf) {
				IsfObject type = getObjectDataType(bf.getBaseDataType());
				return new IsfDataTypeBitField(bf, componentOffset, type);
			}
			IsfObject baseObject = getObjectDataType(IsfUtilities.getBaseDataType(dataType));
			return new IsfDataTypeTypeDef(dataType, baseObject);
		}
		if (dataType.getName().contains(".conflict")) {
			if (!deferredKeys.contains(dataType.getName())) {
				deferredKeys.add(dataType.getName());
			}
		}
		return new IsfDataTypeDefault(dataType);
	}

	/**
	 * Typedef Format: typedef <TYPE_DEF_NAME> <BASE_TYPE_NAME>
	 * 
	 * @throws CancelledException if the action is cancelled by the user
	 */
	private IsfObject getObjectTypeDef(TypeDef typeDef, TaskMonitor monitor)
			throws CancelledException {
		//UNVERIFIED
		DataType dataType = typeDef.getDataType();
		String typedefName = typeDef.getDisplayName();
		String dataTypeName = dataType.getDisplayName();
		if (IsfUtilities.isIntegral(typedefName, dataTypeName)) {
			return new IsfTypedefIntegral(typeDef);
		}

		DataType baseType = typeDef.getBaseDataType();
		try {
			if (baseType instanceof BuiltInDataType builtin) {
				return new IsfTypedefBase(typeDef);
			}
			if (!(baseType instanceof Pointer)) {
				return getIsfObject(dataType, monitor);
			}
			return new IsfTypedefPointer();
		}
		catch (Exception e) {
			Msg.error(this, "TypeDef error: " + e);
		}
		clearResolve(typedefName, baseType);

		return null;
	}

	public JsonElement getTree(Object obj) {
		return gson.toJsonTree(obj);
	}

	public void requestAddress(String key) {
		if (dtm instanceof ProgramDataTypeManager pgmDtm) {
			try {
				Address address = pgmDtm.getProgram().getMinAddress().getAddress(key);
				if (address == null) {
					Msg.error(this, address + " not found");
					return;
				}
				requestedAddresses.add(address);
			}
			catch (AddressFormatException e) {
				e.printStackTrace();
			}
		}
	}

	public void requestSymbol(String symbol) {
		if (symbol == null) {
			Msg.error(this, symbol + " not found");
			return;
		}
		requestedSymbols.add(symbol);
	}

	public void requestType(String path) {
		requestedTypes.add(path);
		DataType dataType = dtm.getDataType(path);
		if (dataType == null) {
			Msg.error(this, path + " not found");
			return;
		}
		requestedDataTypes.add(dataType);
	}

	public void requestType(DataType dataType) {
		if (dataType == null) {
			Msg.error(this, dataType + " not found");
			return;
		}
		requestedDataTypes.add(dataType);
	}

	public JsonWriter getWriter() {
		return writer;
	}

	@Override
	public String toString() {
		return baseWriter.toString();
	}

	public void close() {
		try {
			writer.flush();
			writer.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void setSkipSymbols(boolean val) {
		skipSymbols = val;
	}

	public void setSkipTypes(boolean val) {
		skipTypes = val;
	}

	public void setStrict(boolean val) {
		STRICT = val;
	}
}
