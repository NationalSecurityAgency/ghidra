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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonWriter;

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataOrganizationImpl;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FactoryDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A class used to export data types and symbols as ISF JSON.
 *
 * The ISF JSON should be valid for Volatility is STRICT==true.
 */
public class IsfDataTypeWriter extends AbstractIsfWriter {

	protected Map<DataType, IsfObject> resolved = new HashMap<>();
	private Map<String, DataType> resolvedTypeMap = new HashMap<>();
	public List<String> deferredKeys = new ArrayList<>();

	private Writer baseWriter;

	protected DataTypeManager dtm;
	private DataOrganization dataOrganization;

	protected JsonObject data = new JsonObject();
	protected JsonElement metadata;
	protected JsonElement baseTypes;
	protected JsonElement userTypes;
	protected JsonElement enums;
	protected JsonElement functions;
	protected JsonElement symbols;

	private List<Address> requestedAddresses = new ArrayList<>();
	private List<String> requestedSymbols = new ArrayList<>();
	private List<DataType> requestedDataTypes = new ArrayList<>();
	private boolean skipSymbols = false;
	private boolean skipTypes = false;

	/**
	 * Constructs a new instance of this class using the given writer
	 * 
	 * @param dtm        data-type manager corresponding to target program or null
	 *                   for default
	 * @param baseWriter the writer to use when writing data types
	 * @throws IOException if there is an exception writing the output
	 */
	public IsfDataTypeWriter(DataTypeManager dtm, List<DataType> target, Writer baseWriter)
			throws IOException {
		super(baseWriter);
		this.baseWriter = baseWriter;
		this.dtm = dtm;
		if (dtm != null) {
			dataOrganization = dtm.getDataOrganization();
		}
		if (dataOrganization == null) {
			dataOrganization = DataOrganizationImpl.getDefaultOrganization();
		}

		metadata = new JsonObject();
		baseTypes = new JsonObject();
		userTypes = new JsonObject();
		enums = new JsonObject();
		functions = new JsonObject();
		symbols = new JsonObject();
		requestedDataTypes = target == null ? new ArrayList<>() : target;
		STRICT = true;
	}

	@Override
	public JsonObject getRootObject(TaskMonitor monitor) throws CancelledException, IOException {
		genRoot(monitor);
		return data;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genMetadata();
		genTypes(monitor);
		genSymbols(monitor);

		data.add("metadata", metadata);
		data.add("base_types", baseTypes);
		data.add("user_types", userTypes);
		data.add("enums", enums);
		// Would be nice to support this in the future, but Volatility does not
		// data.add("functions", functions);
		data.add("symbols", symbols);
	}

	public void add(JsonElement parent, String optKey, JsonElement child) {
		if (parent instanceof JsonObject) {
			JsonObject p = (JsonObject) parent;
			p.add(optKey, child);
		}
		if (parent instanceof JsonArray) {
			JsonArray p = (JsonArray) parent;
			p.add(child);
		}
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
			if (metadata instanceof JsonObject) {
				((JsonObject) metadata).addProperty("format", "6.2.0");
			}
			add(metadata, "producer", producer);
			add(metadata, oskey, os);
		}
	}

	private void genSymbols(TaskMonitor monitor) {
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
				add(symbols, entry.getKey(), entry.getValue());
			}
			for (Entry<String, JsonObject> entry : map.entrySet()) {
				if (entry.getKey().startsWith("_")) {
					String nu = entry.getKey().substring(1);
					add(symbols, nu, entry.getValue());
				}
			}
		}
	}

	private void genTypes(TaskMonitor monitor) throws CancelledException, IOException {
		if (skipTypes) {
			return;
		}
		Map<String, DataType> map = new HashMap<>();
		if (requestedDataTypes.isEmpty()) {
			dtm.getAllDataTypes(requestedDataTypes);
			addSingletons();
		}
		monitor.initialize(requestedDataTypes.size());
		for (DataType dataType : requestedDataTypes) {
			String key = dataType.getPathName();
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
		monitor.setMaximum(keylist.size());
		for (String key : keylist) {
			DataType dataType = map.get(key);
			if (DataTypeUtilities.isConflictDataType(dataType)) {
				continue;
			}
			obj = getObjectForDataType(dataType, monitor);
			if (obj == null) {
				continue;
			}
			if (dataType instanceof FunctionDefinition) {
				// Would be nice to support this in the future, but Volatility does not
				add(functions, dataType.getPathName(), obj);
			}
			else if (IsfUtilities.isBaseDataType(dataType)) {
				add(baseTypes, dataType.getPathName(), obj);
			}
			else if (dataType instanceof TypeDef) {
				DataType baseDataType = ((TypeDef) dataType).getBaseDataType();
				if (IsfUtilities.isBaseDataType(baseDataType)) {
					add(baseTypes, dataType.getPathName(), obj);
				}
				else if (baseDataType instanceof Enum) {
					add(enums, dataType.getPathName(), obj);
				}
				else {
					add(userTypes, dataType.getPathName(), obj);
				}
			}
			else if (dataType instanceof Enum) {
				add(enums, dataType.getPathName(), obj);
			}
			else if (dataType instanceof Composite) {
				add(userTypes, dataType.getPathName(), obj);
			}
			monitor.increment();
		}
	}

	private void symbolToJson(Address imageBase, SymbolTable symbolTable,
			Map<String, Symbol> linkages, Map<String, JsonObject> map, Symbol symbol) {
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
			if (address.getAddressSpace().equals(imageBase.getAddressSpace())) {
				sym.addProperty("address", address.subtract(imageBase));
			}
			else {
				sym.addProperty("address", address.getOffset());
			}
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

	@Override
	public void write(JsonObject obj) {
		gson.toJson(obj, writer);
	}

	protected void addSingletons() {
		add(baseTypes, "pointer", getTree(newTypedefPointer(null)));
		add(baseTypes, "undefined", getTree(newTypedefPointer(null)));
	}

	protected JsonObject getObjectForDataType(DataType dt, TaskMonitor monitor)
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
	 * Writes the data type as ISF JSON using the underlying writer. For now,
	 * ignoring top-level bit-fields and function defs as unsupported by ISF.
	 * Typedefs really deserve their own category, but again unsupported.
	 * 
	 * @param dt      the data type to write as ISF JSON
	 * @param monitor the task monitor
	 * @throws IOException if there is an exception writing the output
	 */
	protected IsfObject getIsfObject(DataType dt, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (dt == null) {
			throw new IOException("Null datatype passed to getIsfObject");
		}
		if (dt instanceof FactoryDataType) {
			Msg.error(this, "Factory data types may not be written - type: " + dt);
		}
		if (dt instanceof BitFieldDataType) {
			Msg.error(this, "BitField data types may not be written - type: " + dt);
		}
		if (dt instanceof Pointer || dt instanceof Array) {
			IsfObject type = getObjectDataType(IsfUtilities.getBaseDataType(dt));
			IsfObject obj = newTypedObject(dt, type);
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
		else if (dt instanceof FunctionDefinition) { /// FAIL
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

	public IsfObject resolve(DataType dt) {
		if (resolved.containsKey(dt)) {
			return resolved.get(dt);
		}

		DataType resolvedType = resolvedTypeMap.get(dt.getPathName());
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
			Msg.warn(this, "WARNING! conflicting data type names: " + dt.getPathName() + " - " +
				resolvedType.getPathName());
			return resolved.get(dt);
		}

		resolvedTypeMap.put(dt.getPathName(), dt);
		return null;
	}

	private void clearResolve(String typedefName, DataType baseType) {
		if (baseType instanceof Composite || baseType instanceof Enum) {
			// auto-typedef generated with composite and enum
			if (typedefName.equals(baseType.getPathName())) {
				resolvedTypeMap.remove(typedefName);
				return;
			}
		}
		// Inherited from DataTypeWriter (logic lost to time):
		// A comment explaining the special 'P' case would be helpful!! Smells like
		// fish.
		else if (baseType instanceof Pointer && typedefName.startsWith("P")) {
			DataType dt = ((Pointer) baseType).getDataType();
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}
			if (dt instanceof Composite && dt.getPathName().equals(typedefName.substring(1))) {
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
						return newIsfDynamicComponent(dynamic, type, elementCnt);

					}
					Msg.error(this,
						dynamic.getClass().getSimpleName() + " returned bad replacementBaseType: " +
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

	public IsfObject getObjectDataType(DataType dataType, int componentOffset) {
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
		if (DataTypeUtilities.isConflictDataType(dataType)) {
			if (!deferredKeys.contains(dataType.getPathName())) {
				deferredKeys.add(dataType.getPathName());
			}
		}
		return new IsfDataTypeDefault(dataType);
	}

	/**
	 * Typedef Format: typedef <TYPE_DEF_NAME> <BASE_TYPE_NAME>
	 * 
	 * @throws CancelledException if the action is cancelled by the user
	 */
	protected IsfObject getObjectTypeDef(TypeDef typeDef, TaskMonitor monitor)
			throws CancelledException {
		DataType dataType = typeDef.getDataType();
		String typedefName = typeDef.getPathName();

		DataType baseType = typeDef.getDataType();
		try {
			if (baseType instanceof BuiltInDataType builtin) {
				return newTypedefBase(typeDef);
			}
			if (!(baseType instanceof Pointer)) {
				IsfObject isfObject = getIsfObject(dataType, monitor);
				return newTypedefUser(typeDef, isfObject);
			}
			return newTypedefPointer(typeDef);
		}
		catch (Exception e) {
			Msg.error(this, "TypeDef error: " + e);
		}
		clearResolve(typedefName, baseType);

		return null;
	}

	public void requestAddress(String key) throws IOException {
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
				throw new IOException("Bad address format: " + key);
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

	public JsonWriter getWriter() {
		return writer;
	}

	@Override
	public String toString() {
		return baseWriter.toString();
	}

	public void setSkipSymbols(boolean val) {
		skipSymbols = val;
	}

	public void setSkipTypes(boolean val) {
		skipTypes = val;
	}

	public IsfTypedefBase newTypedefBase(TypeDef typeDef) {
		return new IsfTypedefBase(typeDef);
	}

//	public IsfTypedefIntegral newTypedefIntegral(TypeDef typeDef) {
//		return new IsfTypedefIntegral(typeDef);
//	}

	public IsfTypedefPointer newTypedefPointer(TypeDef typeDef) {
		return new IsfTypedefPointer(typeDef);
	}

	public IsfObject newTypedefUser(TypeDef typeDef, IsfObject object) {
		return object;
	}

	public IsfTypedObject newTypedObject(DataType dt, IsfObject type) {
		return new IsfTypedObject(dt, type);
	}

	public IsfObject newIsfDynamicComponent(Dynamic dynamic, IsfObject type, int elementCnt) {
		return new IsfDynamicComponent(dynamic, type, elementCnt);
	}

}
