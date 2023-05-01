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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.InvalidInputException;

/**
 * A symbol within the decompiler's model of a particular function.  The symbol has a name and a data-type
 * along with other properties. The symbol is mapped to one or more storage locations by attaching a
 * SymbolEntry for each mapping.
 */
public class HighSymbol {

	public static final long ID_BASE = 0x4000000000000000L;	// Put keys in the dynamic symbol portion of the key space
	protected String name;
	protected DataType type;
	protected HighFunction function;	// associated function
	protected int category;				// Sub-class of symbol -1=none 0=parameter 1=equate
	protected int categoryIndex;		// Numbering within the sub-class
	private boolean namelock;		// Is this variable's name locked
	private boolean typelock;		// Is this variable's datatype locked
	private boolean isThis;			// True if we are "this" symbol for function method call
	private boolean isHidden;		// True if we are hidden symbol containing pointer to where return value is stored
	private long id;				// Unique id of this symbol
	protected SymbolEntry[] entryList;	// List of mappings for this symbol

	private HighVariable highVariable;
	protected PcodeDataTypeManager dtmanage;	// Datatype manager for XML generation

	/**
	 * Constructor for use with restoreXML
	 * @param func is the HighFunction using the symbol
	 */
	protected HighSymbol(HighFunction func) {
		function = func;
		dtmanage = function.getDataTypeManager();
		isThis = false;
		isHidden = false;
	}

	/**
	 * Construct a base symbol, given a name and data-type.  Mappings must be attached separately.
	 * @param uniqueId is the id to associate with the new symbol
	 * @param nm is the given name
	 * @param tp is the given data-type
	 * @param func is the function model owning the new symbol
	 */
	protected HighSymbol(long uniqueId, String nm, DataType tp, HighFunction func) {
		function = func;
		dtmanage = function.getDataTypeManager();
		name = nm;
		type = tp;
		namelock = false;
		typelock = false;
		isThis = false;
		isHidden = false;
		id = uniqueId;
		category = -1;
		categoryIndex = -1;
	}

	/**
	 * Construct a symbol that is not attached to a function model. The symbol is given
	 * a name, data-type, and other basic attributes.  Mappings must be attached separately.
	 * @param uniqueId is the id to associate with the new symbol
	 * @param nm is the given name
	 * @param tp is the given data-type
	 * @param tlock is true if the symbol is type locked
	 * @param nlock is true if the symbol is name locked
	 * @param manage is a PcodeDataTypeManager to facilitate XML marshaling
	 */
	protected HighSymbol(long uniqueId, String nm, DataType tp, boolean tlock, boolean nlock,
			PcodeDataTypeManager manage) {
		function = null;
		dtmanage = manage;
		name = nm;
		type = tp;
		namelock = nlock;
		typelock = tlock;
		isThis = false;
		isHidden = false;
		id = uniqueId;
		category = -1;
		categoryIndex = -1;
	}

	protected void addMapEntry(SymbolEntry entry) {
		if (entryList == null) {
			entryList = new SymbolEntry[1];
			entryList[0] = entry;
			if (entry.getStorage().isAutoStorage()) {
				AutoParameterType autoType = entry.getStorage().getAutoParameterType();
				if (autoType == AutoParameterType.THIS) {
					isThis = true;
				}
				else if (autoType == AutoParameterType.RETURN_STORAGE_PTR) {
					isHidden = true;
				}
			}
		}
		else {
			SymbolEntry[] newList = new SymbolEntry[entryList.length + 1];
			for (int i = 0; i < entryList.length; ++i) {
				newList[i] = entryList[i];
			}
			newList[entryList.length] = entry;
			entryList = newList;
		}
	}

	/**
	 * Get id associated with this symbol.
	 * @return the id
	 */
	public long getId() {
		return id;
	}

	/**
	 * Fetch the corresponding database Symbol if it exists.
	 * @return the matching Symbol object or null
	 */
	public Symbol getSymbol() {
		if (id != 0) {
			return getProgram().getSymbolTable().getSymbol(id);
		}
		return null;
	}

	/**
	 * Fetch the namespace owning this symbol, if it exists.
	 * @return the Namespace object or null
	 */
	public Namespace getNamespace() {
		Symbol sym = getSymbol();
		if (sym != null) {
			return sym.getParentNamespace();
		}
		return null;
	}

	/**
	 * Associate a particular HighVariable with this symbol. This is used to link the symbol
	 * into the decompiler's description of how a function manipulates a particular symbol.
	 * Multiple partial HighVariables may get associated with the same HighSymbol.  The HighSymbol
	 * keeps a reference to the biggest HighVariable passed to this method.
	 * @param high is the associated HighVariable
	 */
	void setHighVariable(HighVariable high) {
		if (highVariable != null) {
			if (highVariable.getSize() >= high.getSize()) {
				return;
			}
		}
		highVariable = high;
	}

	/**
	 * Get the HighVariable associate with this symbol if any.  The symbol may have multiple
	 * partial HighVariables associated with it. This method returns the biggest one, which
	 * may not be the same size as the symbol itself.
	 * @return the associated HighVariable or null
	 */
	public HighVariable getHighVariable() {
		return highVariable;
	}

	/**
	 * Get the base name of this symbol
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the Program object containing the function being modeled.
	 * @return the Program
	 */
	public Program getProgram() {
		return dtmanage.getProgram();
	}

	/**
	 * @return the data-type associate with this symbol
	 */
	public DataType getDataType() {
		return type;
	}

	/**
	 * @return the number of bytes consumed by the storage for this symbol
	 */
	public int getSize() {
		return entryList[0].getSize();
	}

	/**
	 * Get the first code Address, within the function, where this symbol's storage actually
	 * holds the value of the symbol.  If there is more than one mapping for the symbol, this
	 * returns the code Address for the first mapping.  A null value indicates that the storage
	 * is valid over the whole function (at least). If the value is non-null, the symbol storage
	 * may be used for other purposes at prior locations.
	 * @return the first use code Address or null
	 */
	public Address getPCAddress() {
		return entryList[0].pcaddr;
	}

	/**
	 * Get the first code Address (expressed as a different in bytes from the starting address of the
	 * function) where this symbol's storage actually holds the value of the symbol. A value of 0 indicates
	 * that the storage is valid across the entire function.  A negative value indicates the storage is
	 * an input to the function.
	 * @return the first-use offset of this symbol's storage
	 */
	protected int getFirstUseOffset() {
		Address pcaddr = entryList[0].pcaddr;
		if (pcaddr == null) {
			return 0;
		}
		return (int) pcaddr.subtract(getHighFunction().getFunction().getEntryPoint());
	}

	/**
	 * Get the function model of which this symbol is a part.
	 * @return the HighFunction owning this symbol
	 */
	public HighFunction getHighFunction() {
		return function;
	}

	/**
	 * Set the category and associated index for this symbol. The category indicates a specific sub-class
	 * of symbols. Currently -1=none, 0=parameter, 1=equate
	 * @param cat is the category
	 * @param index is the category index ("slot" for parameters)
	 */
	protected void setCategory(int cat, int index) {
		category = cat;
		categoryIndex = index;
	}

	/**
	 * Set whether this symbol's data-type is considered "locked". If it is "locked",
	 * this symbol's data-type is considered unchangeable during decompilation. The data-type
	 * will be forced into the decompiler's model of the function to the extent possible.
	 * @param typelock is true if the data-type should be considered "locked".
	 */
	public void setTypeLock(boolean typelock) {
		this.typelock = typelock;
	}

	/**
	 * Set whether this symbol's name is considered "locked". If it is "locked", the decompiler
	 * will use the name when labeling the storage described by this symbol.
	 * @param namelock is true if the name should be considered "locked".
	 */
	public void setNameLock(boolean namelock) {
		this.namelock = namelock;
	}

	/**
	 * If this returns true, this symbol's data-type is "locked", meaning
	 * it is considered unchangeable during decompilation. The data-type
	 * will be forced into the decompiler's model of the function to the extent possible.
	 * @return true if the data-type is considered "locked".
	 */
	public boolean isTypeLocked() {
		return typelock;
	}

	/**
	 * If this returns true, this symbol's name is "locked". meaning the decompiler
	 * is forced to use the name when labeling the storage described by this symbol.
	 * @return true if the name is considered "locked".
	 */
	public boolean isNameLocked() {
		return namelock;
	}

	/**
	 * If this returns true, the decompiler will not speculatively merge this with
	 * other variables.
	 * Currently, being isolated is equivalent to being typelocked.
	 * @return true if this will not be merged with other variables
	 */
	public boolean isIsolated() {
		return typelock;
	}

	/**
	 * @return true if the symbol's value is considered read-only (by the decompiler)
	 */
	public boolean isReadOnly() {
		return entryList[0].isReadOnly();
	}

	/**
	 * Is this symbol a parameter for a function
	 * @return true if this is a parameter
	 */
	public boolean isParameter() {
		return (category == 0);
	}

	/**
	 * For parameters (category=0), this method returns the position of the parameter within the function prototype.
	 * @return the category index for this symbol
	 */
	public int getCategoryIndex() {
		return categoryIndex;
	}

	/**
	 * Is this symbol in the global scope or some other global namespace
	 * @return true if this is global
	 */
	public boolean isGlobal() {
		return false;
	}

	/**
	 * @return true if symbol is a "this" pointer for a class method
	 */
	public boolean isThisPointer() {
		return isThis;
	}

	/**
	 * @return true is symbol holds a pointer to where a function's return value should be stored
	 */
	public boolean isHiddenReturn() {
		return isHidden;
	}

	/**
	 * @return the first mapping object attached to this symbol
	 */
	public SymbolEntry getFirstWholeMap() {
		return entryList[0];
	}

	/**
	 * @return the storage associated with this symbol (associated with the first mapping)
	 */
	public VariableStorage getStorage() {
		return entryList[0].getStorage();
	}

	/**
	 * Encode attributes for the base symbol element
	 * @param encoder is the stream encoder
	 * @throws IOException for errors in the underlying stream
	 */
	protected void encodeHeader(Encoder encoder) throws IOException {
		if ((id >> 56) != (ID_BASE >> 56)) { // Don't send down internal ids
			encoder.writeUnsignedInteger(ATTRIB_ID, id);
		}
		encoder.writeString(ATTRIB_NAME, name);
		encoder.writeBool(ATTRIB_TYPELOCK, typelock);
		encoder.writeBool(ATTRIB_NAMELOCK, namelock);
		encoder.writeBool(ATTRIB_READONLY, isReadOnly());
		boolean isVolatile = entryList[0].isVolatile();
		if (isVolatile) {
			encoder.writeBool(ATTRIB_VOLATILE, true);
		}
		if (isIsolated()) {
			encoder.writeBool(ATTRIB_MERGE, false);
		}
		if (isThis) {
			encoder.writeBool(ATTRIB_THISPTR, true);
		}
		if (isHidden) {
			encoder.writeBool(ATTRIB_HIDDENRETPARM, true);
		}
		encoder.writeSignedInteger(ATTRIB_CAT, category);
		if (categoryIndex >= 0) {
			encoder.writeUnsignedInteger(ATTRIB_INDEX, categoryIndex);
		}
	}

	/**
	 * Encode the symbol description as an element to the stream.  This does NOT save the mappings.
	 * @param encoder is the stream encoder
	 * @throws IOException for errors in the underlying stream
	 */
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_SYMBOL);
		encodeHeader(encoder);
		dtmanage.encodeTypeRef(encoder, type, getSize());
		encoder.closeElement(ELEM_SYMBOL);
	}

	protected void decodeHeader(Decoder decoder) throws DecoderException {
		name = null;
		id = 0;
		typelock = false;
		namelock = false;
		isThis = false;
		isHidden = false;
		categoryIndex = -1;
		category = -1;

		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_ID.id()) {
				id = decoder.readUnsignedInteger();
			}
			else if (attribId == ATTRIB_TYPELOCK.id()) {
				typelock = decoder.readBool();
			}
			else if (attribId == ATTRIB_NAMELOCK.id()) {
				namelock = decoder.readBool();
			}
			else if (attribId == ATTRIB_THISPTR.id()) {
				isThis = decoder.readBool();
			}
			else if (attribId == ATTRIB_HIDDENRETPARM.id()) {
				isHidden = decoder.readBool();
			}
			else if (attribId == ATTRIB_NAME.id()) {
				name = decoder.readString();
			}
			else if (attribId == ATTRIB_CAT.id()) {
				category = (int) decoder.readSignedInteger();
			}
			else if (attribId == ATTRIB_INDEX.id()) {
				categoryIndex = (int) decoder.readUnsignedInteger();
			}
		}
		if (id == 0) {
			throw new DecoderException("missing unique symbol id");
		}
	}

	/**
	 * Decode this symbol object and its associated mappings from the stream.
	 * @param decoder is the stream decoder
	 * @throws DecoderException for invalid encodings
	 */
	public void decode(Decoder decoder) throws DecoderException {
		int symel = decoder.openElement(ELEM_SYMBOL);
		decodeHeader(decoder);
		type = dtmanage.decodeDataType(decoder);
		decoder.closeElement(symel);

		if (categoryIndex >= 0 && name.startsWith("$$undef")) {
			// use default parameter name
			name = "param_" + Integer.toString(categoryIndex + 1);
		}

		for (;;) {
			int el = decoder.peekElement();
			if (el == 0) {
				break;
			}
			SymbolEntry entry;
			if (el == ELEM_HASH.id()) {
				entry = new DynamicEntry(this);
			}
			else if (this instanceof HighCodeSymbol) {
				entry = new MappedDataEntry(this);
			}
			else {
				entry = new MappedEntry(this);
			}
			entry.decode(decoder);
			addMapEntry(entry);
		}
		if ((isThis || isHidden) && entryList != null) {
			SymbolEntry entry = entryList[0];
			VariableStorage storage = entry.getStorage();
			AutoParameterType autoType =
				isThis ? AutoParameterType.THIS : AutoParameterType.RETURN_STORAGE_PTR;
			try {
				VariableStorage newStorage = new DynamicVariableStorage(
					storage.getProgramArchitecture(), autoType, storage.getFirstVarnode());
				entryList[0] = new MappedEntry(this, newStorage, entry.getPCAdress());
			}
			catch (InvalidInputException e) {
				throw new DecoderException("Unable to parse auto-parameter");
			}
		}
	}

	/**
	 * Restore a full HighSymbol from the next &lt;mapsym&gt; element in the stream.
	 * This method acts as a HighSymbol factory, instantiating the correct class
	 * based on the particular elements.
	 * @param decoder is the stream decoder
	 * @param isGlobal is true if this symbol is being read into a global scope
	 * @param high is the function model that will own the new symbol
	 * @return the new symbol
	 * @throws DecoderException for invalid encodings
	 */
	public static HighSymbol decodeMapSym(Decoder decoder, boolean isGlobal, HighFunction high)
			throws DecoderException {
		HighSymbol res = null;
		int mapel = decoder.openElement(ELEM_MAPSYM);
		int symel = decoder.peekElement();
		if (symel == ELEM_EQUATESYMBOL.id()) {
			res = new EquateSymbol(high);
		}
		else if (isGlobal) {
//			res = new HighCodeSymbol(high);
			// Currently the decompiler does not send back global symbols. They are inferred from the HighVariables
		}
		else {
			res = new HighSymbol(high);
		}
		res.decode(decoder);
		for (;;) {
			SymbolEntry entry;
			int subid = decoder.peekElement();
			if (subid == 0) {
				break;
			}
			if (subid == ELEM_HASH.id()) {
				entry = new DynamicEntry(res);
			}
			else {
				entry = new MappedEntry(res);
			}
			entry.decode(decoder);
			res.addMapEntry(entry);
		}
		decoder.closeElement(mapel);
		return res;
	}

	/**
	 * Encode the given symbol with all its mapping as a &lt;mapsym&gt; element to the stream.
	 * @param encoder is the stream encoder
	 * @param sym is the given symbol
	 * @throws IOException for errors in the underlying stream
	 */
	public static void encodeMapSym(Encoder encoder, HighSymbol sym) throws IOException {
		encoder.openElement(ELEM_MAPSYM);
		sym.encode(encoder);
		for (SymbolEntry entry : sym.entryList) {
			entry.encode(encoder);
		}
		encoder.closeElement(ELEM_MAPSYM);
	}
}
