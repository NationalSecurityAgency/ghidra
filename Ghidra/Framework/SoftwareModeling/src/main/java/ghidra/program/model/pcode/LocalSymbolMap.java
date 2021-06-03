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
package ghidra.program.model.pcode;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A container for local symbols within the decompiler's model of a function. It contains HighSymbol
 * objects for any symbol within the scope of the function, including parameters. The container is populated
 * either from the underlying Function object (when sending information to the decompiler) or read in from
 * an XML description (when receiving a function model from the decompiler). HighSymbols can be obtained
 * via Address using findLocal() or by id using getSymbol().  Parameters can be accessed specifically
 * using getParamSymbol().
 */
public class LocalSymbolMap {
	private HighFunction func;				// Function to which these variables are local
	private String spacename;
	private HashMap<MappedVarKey, HighSymbol> addrMappedSymbols;	// Hashed by addr and pcaddr
	private HashMap<Long, HighSymbol> symbolMap;  			// Hashed by unique key
	private HighSymbol[] paramSymbols;
	private long uniqueSymbolId;		// Next available symbol id

	/**
	 * @param highFunc HighFunction the local variables are defined within.
	 * @param spcname space name the local variables are defined within.
	 */
	public LocalSymbolMap(HighFunction highFunc, String spcname) {
		func = highFunc;
		spacename = spcname;
		addrMappedSymbols = new HashMap<MappedVarKey, HighSymbol>();
		symbolMap = new HashMap<Long, HighSymbol>();
		paramSymbols = new HighSymbol[0];
		uniqueSymbolId = 0;
	}

	/**
	 * Get the decompiler's function model owning this container
	 * @return the owning HighFunction
	 */
	public HighFunction getHighFunction() {
		return func;
	}

	/**
	 * Assign a unique id to a new symbol being put in this container.
	 * @return the unique id
	 */
	private long getNextId() {
		long key = HighSymbol.ID_BASE + uniqueSymbolId;
		uniqueSymbolId += 1;
		return key;
	}

	/**
	 * Construct and return a map from a HighSymbol's name to the HighSymbol object
	 * @return the new name to symbol map
	 */
	public Map<String, HighSymbol> getNameToSymbolMap() {
		Map<String, HighSymbol> newMap = new TreeMap<String, HighSymbol>();
		for (HighSymbol highSymbol : symbolMap.values()) {
			newMap.put(highSymbol.getName(), highSymbol);
		}
		return newMap;
	}

	/**
	 * Remove the given HighSymbol from this container.
	 * The key is removed from the main symbolMap.  It is also removed from the MappedEntry map
	 * and from the list of parameter symbols if applicable.
	 * @param highSymbol is the given symbol
	 */
	private void removeSymbol(HighSymbol highSymbol) {
		SymbolEntry mapEntry = highSymbol.getFirstWholeMap();
		if (mapEntry instanceof MappedEntry) {
			MappedVarKey key = new MappedVarKey(mapEntry.getStorage(), mapEntry.getPCAdress());
			addrMappedSymbols.remove(key);
		}
		symbolMap.remove(highSymbol.getId());
		if (highSymbol.isParameter()) {
			int index = highSymbol.getCategoryIndex();
			HighSymbol[] newArray = new HighSymbol[paramSymbols.length - 1];
			for (int i = 0; i < index; ++i) {
				newArray[i] = paramSymbols[i];
			}
			for (int i = index + 1; i < paramSymbols.length; ++i) {
				HighSymbol paramSym = paramSymbols[i];
				newArray[i - 1] = paramSym;
				paramSym.categoryIndex -= 1;
			}
		}
	}

	/**
	 * Given names of the form:  "baseName", "baseName$1", "baseName@2", ...
	 * find the corresponding HighSymbols in this container and merge them into a single HighSymbol.
	 * The name passed into this method must be of the form "baseName$1", the base name is extracted from it.
	 * @param name is a string with the base name concatenated with "$1"
	 * @param nameMap is a map from all symbols names in this container to the corresponding HighSymbol
	 */
	private void mergeNamedSymbols(String name, Map<String, HighSymbol> nameMap) {
		String baseName = name.substring(0, name.length() - 2);
		HighSymbol baseSymbol = nameMap.get(baseName);
		if (baseSymbol == null || !baseSymbol.isTypeLocked() ||
			(baseSymbol instanceof EquateSymbol)) {
			return;
		}
		DataType baseDataType = baseSymbol.getDataType();
		for (int index = 1;; ++index) {
			String nextName = baseName + '$' + Integer.toString(index);
			HighSymbol nextSymbol = nameMap.get(nextName);
			if (nextSymbol == null || !nextSymbol.isTypeLocked() || nextSymbol.isParameter() ||
				(baseSymbol instanceof EquateSymbol)) {
				break;
			}
			if (!nextSymbol.getDataType().equals(baseDataType)) {	// Data-types of symbols being merged must match
				break;
			}
			SymbolEntry mapEntry = nextSymbol.getFirstWholeMap();
			if (mapEntry.getPCAdress() == null) {					// Don't merge from an address tied symbol
				break;
			}
			baseSymbol.addMapEntry(mapEntry);
			removeSymbol(nextSymbol);
		}
	}

	/**
	 * Populate the local variable map from information attached to the Program DB's function.
	 * @param includeDefaultNames is true if default symbol names should be considered locked
	 */
	public void grabFromFunction(boolean includeDefaultNames) {
		ArrayList<String> mergeNames = null;
		Function dbFunction = func.getFunction();
		Variable locals[] = dbFunction.getLocalVariables();
		for (Variable local : locals) {
			if (!local.isValid()) {
				// exclude locals which don't have valid storage
				continue;
			}
			DataType dt = local.getDataType();
			boolean istypelock = true;
			boolean isnamelock = true;
			if (Undefined.isUndefined(dt)) {
				istypelock = false;
			}
			String name = local.getName();
			if (name.length() > 2 && name.charAt(name.length() - 2) == '$') {
				// An indication of names like "name", "name@1", "name@2"
				if (name.charAt(name.length() - 1) == '1') {
					if (mergeNames == null) {
						mergeNames = new ArrayList<String>();
					}
					mergeNames.add(name);
				}
			}

			VariableStorage storage = local.getVariableStorage();
			long id = 0;
			Symbol symbol = local.getSymbol();
			if (symbol != null) {
				id = symbol.getID();
			}
			HighSymbol sym;
			if (storage.isHashStorage()) {
				Address defAddr = dbFunction.getEntryPoint().addWrap(local.getFirstUseOffset());
				sym =
					newDynamicSymbol(id, name, dt, storage.getFirstVarnode().getOffset(), defAddr);
			}
			else {
				Address defAddr = null;
				int addrType = storage.getFirstVarnode().getAddress().getAddressSpace().getType();
				if (addrType != AddressSpace.TYPE_STACK && addrType != AddressSpace.TYPE_RAM) {
					defAddr = dbFunction.getEntryPoint().addWrap(local.getFirstUseOffset());
				}
				sym = newMappedSymbol(id, name, dt, storage, defAddr, -1);
			}
			sym.setTypeLock(istypelock);
			sym.setNameLock(isnamelock);
		}

		Parameter[] p = dbFunction.getParameters();
		boolean lock = (dbFunction.getSignatureSource() != SourceType.DEFAULT);

		Address pcaddr = dbFunction.getEntryPoint();
		pcaddr = pcaddr.subtractWrap(1);

		List<HighSymbol> paramList = new ArrayList<HighSymbol>();
		for (int i = 0; i < p.length; ++i) {
			Parameter var = p[i];
			if (!var.isValid()) {
				// TODO: exclude parameters which don't have valid storage ??
				continue;
			}
			DataType dt = var.getDataType();
			String name = var.getName();
			if (name.length() > 2 && name.charAt(name.length() - 2) == '$') {
				// An indication of names like "name", "name@1", "name@2"
				if (name.charAt(name.length() - 1) == '1') {
					if (mergeNames == null) {
						mergeNames = new ArrayList<String>();
					}
					mergeNames.add(name);
				}
			}
			VariableStorage storage = var.getVariableStorage();
			Address resAddr = storage.isStackStorage() ? null : pcaddr;
			long id = 0;
			Symbol symbol = var.getSymbol();
			if (symbol != null) {
				id = symbol.getID();
			}
			HighSymbol paramSymbol = newMappedSymbol(id, name, dt, storage, resAddr, i);
			paramList.add(paramSymbol);
			boolean namelock = true;
			if (!includeDefaultNames) {
				namelock = isUserDefinedName(name);
			}
			paramSymbol.setNameLock(namelock);
			paramSymbol.setTypeLock(lock);
		}

		paramSymbols = new HighSymbol[paramList.size()];
		paramList.toArray(paramSymbols);
		Arrays.sort(paramSymbols, PARAM_SYMBOL_SLOT_COMPARATOR);

		grabEquates(dbFunction);
		grabMerges(mergeNames);
	}

	private boolean isUserDefinedName(String name) {
		if (name.startsWith("local_")) {
			return false;
		}
		if (name.startsWith("param_")) {
			return false;
		}
		return true;
	}

	/**
	 * Parse a &lt;mapsym&gt; tag in XML
	 * @param parser is the XML parser
	 * @return the reconstructed HighSymbol
	 * @throws PcodeXMLException for problems sub tags
	 */
	private HighSymbol parseSymbolXML(XmlPullParser parser) throws PcodeXMLException {
		HighSymbol res = HighSymbol.restoreMapSymXML(parser, false, func);
		insertSymbol(res);
		return res;
	}

	/**
	 * Parse a local symbol scope in XML from the &lt;localdb&gt; tag.
	 * 
	 * @param parser is the XML parser
	 * @throws PcodeXMLException for problems parsing individual tags
	 */
	public void parseScopeXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("localdb");
		spacename = el.getAttribute("main");
		XmlElement scopeel = parser.start("scope");

		parser.discardSubTree();	// This is the parent scope path
		parser.discardSubTree();	// This is the address range

		addrMappedSymbols.clear();			// Clear out any old map
		symbolMap.clear();			// Clear out any old map

		XmlElement nextEl = parser.peek();
		if (nextEl != null && nextEl.isStart() && "symbollist".equals(nextEl.getName())) {
			parseSymbolList(parser);
		}
		parser.end(scopeel);
		parser.end(el);
	}

	private static final Comparator<HighSymbol> PARAM_SYMBOL_SLOT_COMPARATOR =
		new Comparator<HighSymbol>() {
			@Override
			public int compare(HighSymbol sym1, HighSymbol sym2) {
				return sym1.getCategoryIndex() - sym2.getCategoryIndex();
			}
		};

	/**
	 * Add mapped symbols to this LocalVariableMap, by parsing the &lt;symbollist&gt; and &lt;mapsym&gt; tags.
	 * @param parser is the XML parser
	 * @throws PcodeXMLException for problems parsing a tag
	 */
	public void parseSymbolList(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("symbollist");
		ArrayList<HighSymbol> parms = new ArrayList<HighSymbol>();
		while (parser.peek().isStart()) {
			HighSymbol sym = parseSymbolXML(parser);
			if (sym.isParameter()) {
				parms.add(sym);
			}
		}
		paramSymbols = new HighSymbol[parms.size()];
		parms.toArray(paramSymbols);
		Arrays.sort(paramSymbols, PARAM_SYMBOL_SLOT_COMPARATOR);
		parser.end(el);
	}

	/**
	 * Output an XML document representing this local variable map.
	 * @param resBuf is the buffer to write to
	 * @param namespace if the namespace of the function
	 */
	public void buildLocalDbXML(StringBuilder resBuf, Namespace namespace) {		// Get memory mapped local variables
		resBuf.append("<localdb");
		SpecXmlUtils.encodeBooleanAttribute(resBuf, "lock", false);
		SpecXmlUtils.encodeStringAttribute(resBuf, "main", spacename);
		resBuf.append(">\n");
		resBuf.append("<scope");
		SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", func.getFunction().getName());
		resBuf.append(">\n");
		resBuf.append("<parent");
		long parentid = Namespace.GLOBAL_NAMESPACE_ID;
		if (!HighFunction.collapseToGlobal(namespace)) {
			parentid = namespace.getID();
		}
		SpecXmlUtils.encodeUnsignedIntegerAttribute(resBuf, "id", parentid);
		resBuf.append("/>\n");
		resBuf.append("<rangelist/>\n");	// Empty address range
		resBuf.append("<symbollist>\n");
		Iterator<HighSymbol> iter = symbolMap.values().iterator();
		while (iter.hasNext()) {
			HighSymbol sym = iter.next();
			HighSymbol.buildMapSymXML(resBuf, sym);
		}
		resBuf.append("</symbollist>\n");
		resBuf.append("</scope>\n");
		resBuf.append("</localdb>\n");
	}

	/**
	 * Get all the symbols mapped for this program, Param, Locals.
	 * The HighSymbol can either be a HighParam, or HighLocal
	 * 
	 * @return an iterator over all mapped symbols.
	 */
	public Iterator<HighSymbol> getSymbols() {
		return symbolMap.values().iterator();
	}

	/**
	 * Find any local variable (including input params) by address
	 * @param store - variable storage
	 * @param pc = Address of first use, or null if address
	 *             is valid throughout the entire scope
	 * @return HighLocal or null
	 */
	public HighSymbol findLocal(VariableStorage store, Address pc) {
		MappedVarKey key = new MappedVarKey(store, pc);
		return addrMappedSymbols.get(key);
	}

	/**
	 * Find any local variable (including input params) by address
	 * @param addr - variable storage address
	 * @param pc = Address of first use, or null if address
	 *             is valid throughout the entire scope
	 * @return HighLocal or null
	 */
	public HighSymbol findLocal(Address addr, Address pc) {
		MappedVarKey key = new MappedVarKey(addr, pc);
		return addrMappedSymbols.get(key);
	}

	/**
	 * Lookup high variable based upon its symbol-id
	 * @param id symbol-id
	 * @return variable or null if not found
	 */
	public HighSymbol getSymbol(long id) {
		return symbolMap.get(id);
	}

	/**
	 * Get the number of parameter symbols in this scope
	 * @return the number of parameters
	 */
	public int getNumParams() {
		return paramSymbols.length;
	}

	/**
	 * @param i is the desired parameter position
	 * @return the i-th parameter HighSymbol
	 */
	public HighSymbol getParamSymbol(int i) {
		return paramSymbols[i];
	}

	/**
	 * @param i is the desired parameter position
	 * @return the i-th parameter variable
	 */
	public HighParam getParam(int i) {
		return (HighParam) paramSymbols[i].getHighVariable();
	}

	public boolean containsVariableWithName(String name) {
		Collection<HighSymbol> values = symbolMap.values();
		for (HighSymbol sym : values) {
			if (sym.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}

	protected HighSymbol newMappedSymbol(long id, String nm, DataType dt, VariableStorage store,
			Address pcaddr, int slot) {
		if (id == 0) {
			id = getNextId();
		}
		HighSymbol sym = new HighSymbol(id, nm, dt, func);
		if (slot >= 0) {
			sym.setCategory(0, slot);
		}
		MappedEntry entry = new MappedEntry(sym, store, pcaddr);
		sym.addMapEntry(entry);
		insertSymbol(sym);
		return sym;
	}

	protected HighSymbol newDynamicSymbol(long id, String nm, DataType dt, long hash,
			Address pcaddr) {
		if (id == 0) {
			id = getNextId();
		}
		HighSymbol sym = new HighSymbol(id, nm, dt, func);
		DynamicEntry entry = new DynamicEntry(sym, pcaddr, hash);
		sym.addMapEntry(entry);
		insertSymbol(sym);
		return sym;
	}

	private void insertSymbol(HighSymbol sym) {
		long uniqueId = sym.getId();
		if ((uniqueId >> 56) == (HighSymbol.ID_BASE >> 56)) {
			long val = uniqueId & 0x7fffffff;
			if (val > uniqueSymbolId) {
				uniqueSymbolId = val;
			}
		}
		if (sym.entryList[0] instanceof MappedEntry) {
			MappedVarKey key = new MappedVarKey(sym.getStorage(), sym.getPCAddress());
			addrMappedSymbols.put(key, sym);
		}
		symbolMap.put(uniqueId, sym);
	}

	private EquateSymbol newEquateSymbol(long uniqueId, String nm, long val, long hash,
			Address addr) {
		EquateSymbol eqSymbol;
		if (uniqueId == 0) {
			uniqueId = getNextId();
		}
		int conv = EquateSymbol.convertName(nm, val);
		if (conv < 0) {
			eqSymbol = new EquateSymbol(uniqueId, nm, val, func, addr, hash);
			eqSymbol.setNameLock(true);
		}
		else {
			eqSymbol = new EquateSymbol(uniqueId, conv, val, func, addr, hash);
		}
		//Do NOT setTypeLock
		return eqSymbol;
	}

	/**
	 * Build dynamic symbols based on equates
	 * @param dbFunction is the function to pull equates for
	 */
	private void grabEquates(Function dbFunction) {
		// Find named constants via Equates
		Program program = dbFunction.getProgram();
		EquateTable equateTable = program.getEquateTable();
		Listing listing = program.getListing();
		AddressIterator equateAddresses = equateTable.getEquateAddresses(dbFunction.getBody());
		while (equateAddresses.hasNext()) {
			Address defAddr = equateAddresses.next();
			for (Equate eq : equateTable.getEquates(defAddr)) {
				Instruction instr = listing.getInstructionAt(defAddr);
				if (instr == null) {
					continue;
				}
				long hash[] = DynamicHash.calcConstantHash(instr, eq.getValue());
				if (hash.length == 0) {
					continue;
				}
				Arrays.sort(hash);		// Sort in preparation for deduping
				String displayName = eq.getDisplayName();
				long eqValue = eq.getValue();

				EquateSymbol eqSymbol;
				for (int i = 0; i < hash.length; ++i) {
					if (i != 0 && hash[i - 1] == hash[i]) {
						continue;		// Found a duplicate, skip it
					}
					eqSymbol = newEquateSymbol(0, displayName, eqValue, hash[i], defAddr);
					symbolMap.put(eqSymbol.getId(), eqSymbol);
				}
			}
		}
	}

	private void grabMerges(ArrayList<String> mergeNames) {
		if (mergeNames == null) {
			return;
		}
		Map<String, HighSymbol> nameToSymbolMap = getNameToSymbolMap();
		for (String name : mergeNames) {
			mergeNamedSymbols(name, nameToSymbolMap);
		}
	}

	/**
	 * Hashing keys for Local variables
	 */
	class MappedVarKey {
		private Address addr;
		private Address pcaddr;

		public MappedVarKey(Address addr, Address pcad) {
			this.addr = addr;
			if (!addr.isStackAddress()) {
				// first use not supported for stack
				pcaddr = pcad;
			}
		}

		public MappedVarKey(VariableStorage store, Address pcad) {
			addr = store.getFirstVarnode().getAddress();
			if (!addr.isStackAddress()) {
				// first use not supported for stack
				pcaddr = pcad;
			}
		}

		@Override
		public boolean equals(Object op2) {
			MappedVarKey op = (MappedVarKey) op2;
			if (!SystemUtilities.isEqual(pcaddr, op.pcaddr)) {
				return false;
			}
			return addr.equals(op.addr);
		}

		@Override
		public int hashCode() {
			int hash1 = addr.hashCode();
			int hash2 = pcaddr != null ? pcaddr.hashCode() : 0;
			return (hash1 << 4) ^ hash2;
		}
	}

}
