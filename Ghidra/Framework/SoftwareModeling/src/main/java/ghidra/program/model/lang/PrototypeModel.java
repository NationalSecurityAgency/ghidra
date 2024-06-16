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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.SystemUtilities;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * A function calling convention model.
 * Formal specification of how a compiler passes
 * arguments between functions.
 */
public class PrototypeModel {
	public static final int UNKNOWN_EXTRAPOP = 0x8000;

	protected String name; // Name of model
	protected boolean isExtension;		// True if this model is a Program specific extension
	private int extrapop; // change in stackpointer
	// across function calls
	private int stackshift; // change in stackpointer
	// due to call mechanism
	private ParamList inputParams; // (possible) parameter locations
	private ParamList outputParams;
	private Varnode[] unaffected;	// Memory ranges unaffected by calls
	private Varnode[] killedbycall;	// Memory ranges definitely affected by calls
	private Varnode[] returnaddress;	// Memory used to store the return address
	private Varnode[] likelytrash;	// Memory likely to be meaningless on input
	private Varnode[] internalstorage;	// Registers holding internal compiler constants
	private PrototypeModel compatModel;	// The model this is an alias of
	private AddressSet localRange;	// Range on the stack considered for local storage
	private AddressSet paramRange;	// Range on the stack considered for parameter storage
	private InputListType inputListType = InputListType.STANDARD;
	private boolean hasThis;		// Convention has a this (auto-parameter)
	private boolean isConstruct;		// Convention is used for object construction
	private boolean hasUponEntry;	// Does this have an uponentry injection
	private boolean hasUponReturn;	// Does this have an uponreturn injection

	/**
	 * Create a named alias of another PrototypeModel.
	 * All elements of the original model are copied except:
	 *   1) The name
	 *   2) The generic calling convention (which is based on name)
	 *   3) The hasThis property (which allows __thiscall to alias something else)
	 *   4) The "fact of" the model being an alias
	 * @param name is the name of the alias
	 * @param model is the other PrototypeModel
	 */
	public PrototypeModel(String name, PrototypeModel model) {
		this.name = name;
		isExtension = false;
		extrapop = model.extrapop;
		stackshift = model.stackshift;
		inputListType = model.inputListType;
		inputParams = model.inputParams;
		outputParams = model.outputParams;
		unaffected = model.unaffected;
		killedbycall = model.killedbycall;
		returnaddress = model.returnaddress;
		likelytrash = model.likelytrash;
		internalstorage = model.internalstorage;
		compatModel = model;
		localRange = new AddressSet(model.localRange);
		paramRange = new AddressSet(model.paramRange);
		hasThis = model.hasThis || name.equals(CompilerSpec.CALLING_CONVENTION_thiscall);
		isConstruct = model.isConstruct;
		hasUponEntry = model.hasUponEntry;
		hasUponReturn = model.hasUponReturn;
	}

	public PrototypeModel() {
		name = null;
		isExtension = false;
		extrapop = PrototypeModel.UNKNOWN_EXTRAPOP;
		stackshift = -1;
		inputParams = null;
		outputParams = null;
		unaffected = null;
		killedbycall = null;
		returnaddress = null;
		likelytrash = null;
		internalstorage = null;
		compatModel = null;
		localRange = null;
		paramRange = null;
		hasThis = false;
		isConstruct = false;
		hasUponEntry = false;
		hasUponReturn = false;
	}

	/**
	 * @return list of registers unaffected by called functions
	 */
	public Varnode[] getUnaffectedList() {
		if (unaffected == null) {
			unaffected = new Varnode[0];
		}
		return unaffected;
	}

	/**
	 * @return list of registers definitely affected by called functions
	 */
	public Varnode[] getKilledByCallList() {
		if (killedbycall == null) {
			killedbycall = new Varnode[0];
		}
		return killedbycall;
	}

	/**
	 * @return list of registers whose input value is likely meaningless
	 */
	public Varnode[] getLikelyTrash() {
		if (likelytrash == null) {
			likelytrash = new Varnode[0];
		}
		return likelytrash;
	}

	/**
	 * @return list of registers used to store internal compiler constants
	 */
	public Varnode[] getInternalStorage() {
		if (internalstorage == null) {
			internalstorage = new Varnode[0];
		}
		return internalstorage;
	}

	/**
	 * @return list of registers/memory used to store the return address
	 */
	public Varnode[] getReturnAddress() {
		return returnaddress;
	}

	/**
	 * If this returns true, it indicates this model is an artificial merge of other models.
	 * A merged model can be used as part of the analysis process when attempting to distinguish
	 * between different possible models for an unknown function.
	 * @return true if this model is an artificial merge of other models
	 */
	public boolean isMerged() {
		return false;
	}

	/**
	 * @return true if this model is a Program specific extension to the CompilerSpec
	 */
	public boolean isProgramExtension() {
		return isExtension;
	}

	/**
	 * @return the formal name of the model
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the number of extra bytes popped from the stack when a function that uses
	 * this model returns to its caller. This is usually just the number of bytes used to
	 * store the return value, but some conventions may do additional clean up of stack parameters.
	 * A special value of UNKNOWN_EXTRAPOP indicates that the number of bytes is unknown.  
	 * @return the number of extra bytes popped
	 */
	public int getExtrapop() {
		return extrapop;
	}

	/**
	 * @return the number of bytes on the stack used, by this model, to store the return value
	 */
	public int getStackshift() {
		return stackshift;
	}

	/**
	 * @return true if this model has an implied "this" parameter for referencing class data
	 */
	public boolean hasThisPointer() {
		return hasThis;
	}

	/**
	 * @return true if this model is used specifically for class constructors
	 */
	public boolean isConstructor() {
		return isConstruct;
	}

	/**
	 * @return the allocation strategy for this model
	 */
	public InputListType getInputListType() {
		return inputListType;
	}

	/**
	 * Return true if this model has specific p-code injections associated with it
	 * (either an "uponentry" or "uponreturn" payload),
	 * which are used to decompile functions with this model. 
	 * @return true if this model uses p-code injections
	 */
	public boolean hasInjection() {
		return hasUponEntry || hasUponReturn;
	}

	/**
	 * Get the preferred return location given the specified dataType.
	 * If the return value is passed back through a hidden input pointer,
	 * i.e. {@link AutoParameterType#RETURN_STORAGE_PTR}, this routine will not pass back
	 * the storage location of the pointer, but will typically pass
	 * back the location of the normal return register which holds a copy of the pointer.
	 * @param dataType first parameter dataType or null for an undefined type.
	 * @param program is the Program
	 * @return return location or {@link VariableStorage#UNASSIGNED_STORAGE} if
	 * unable to determine suitable location
	 */
	public VariableStorage getReturnLocation(DataType dataType, Program program) {
		DataType clone = dataType.clone(program.getDataTypeManager());
		PrototypePieces proto = new PrototypePieces(this, clone);
		ArrayList<ParameterPieces> res = new ArrayList<>();
		outputParams.assignMap(proto, program.getDataTypeManager(), res, false);
		if (res.size() > 0) {
			return res.get(0).getVariableStorage(program);
		}
		return null;
	}

	/**
	 * Get the preferred parameter location for a new parameter which will appended
	 * to the end of an existing set of params.  If existing parameters use custom
	 * storage, this method should not be used.
	 * @param params existing set parameters to which the next parameter will
	 * be appended. (may be null)
	 * @param dataType dataType associated with next parameter location or null
	 * for a default undefined type.
	 * @param program is the Program
	 * @return next parameter location or {@link VariableStorage#UNASSIGNED_STORAGE} if
	 * unable to determine suitable location
	 */
	public VariableStorage getNextArgLocation(Parameter[] params, DataType dataType,
			Program program) {
		return getArgLocation(params != null ? params.length : 0, params, dataType, program);
	}

	/**
	 * Get the preferred parameter location for a specified index,
	 * which will be added/inserted within the set of existing function params.
	 * If existing parameters use custom storage, this method should not be used.
	 * @param argIndex is the index
	 * @param params existing set parameters to which the parameter specified by
	 * argIndex will be added/inserted be appended (may be null).
	 * @param dataType dataType associated with next parameter location or null
	 * for a default undefined type.
	 * @param program is the Program
	 * @return parameter location or {@link VariableStorage#UNASSIGNED_STORAGE} if
	 * unable to determine suitable location
	 */
	public VariableStorage getArgLocation(int argIndex, Parameter[] params, DataType dataType,
			Program program) {

		if (dataType != null) {
			dataType = dataType.clone(program.getDataTypeManager());
			// Identify next arg index based upon number of storage varnodes 
			// already assigned to parameters - this may not work well if
			// customized storage has been used
		}

		DataType arr[] = new DataType[argIndex + 2];
		arr[0] = VoidDataType.dataType;				// Assume the return type is void
		for (int i = 0; i < argIndex; ++i) {
			if (params != null && i < params.length) {
				arr[i + 1] = params[i].getDataType();			// Copy in current types if we have them
			}
			else {
				arr[i + 1] = DataType.DEFAULT;				// Otherwise assume default (integer) type
			}
		}
		arr[argIndex + 1] = dataType;

		VariableStorage res[] = getStorageLocations(program, arr, false);
		return res[res.length - 1];
	}

	/**
	 * Calculate input and output storage locations given a function prototype
	 * 
	 * The data-types of the function prototype are passed in. Based on this model, a
	 * location is selected for each (input and output) parameter and passed back to the
	 * caller.  The passed back storage locations are ordered with the output storage
	 * as the first entry, followed by the input storage locations.  The model has the option
	 * of inserting a hidden return value pointer in the input storage locations.
	 * 
	 * If the model cannot assign storage, the ParameterPieces will have a null Address.
	 * @param proto is the function prototype parameter data-types
	 * @param dtManager is the manager used to create indirect data-types
	 * @param res will hold the storage addresses for each parameter
	 * @param addAutoParams is true if auto parameters (like the this pointer) should be processed
	 */
	public void assignParameterStorage(PrototypePieces proto, DataTypeManager dtManager,
			ArrayList<ParameterPieces> res, boolean addAutoParams) {
		outputParams.assignMap(proto, dtManager, res, addAutoParams);
		inputParams.assignMap(proto, dtManager, res, addAutoParams);

		if (hasThis && addAutoParams && res.size() > 1) {
			int thisIndex = 1;
			if (res.get(1).hiddenReturnPtr && res.size() > 2) {
				if (inputParams.isThisBeforeRetPointer()) {
					// pointer has been bumped by auto-return-storage
					res.get(1).swapMarkup(res.get(2));	// must swap storage and position for slots 1 and 2
				}
				else {
					thisIndex = 2;
				}
			}
			res.get(thisIndex).isThisPointer = true;
		}
	}

	/**
	 * Compute the variable storage for a given array of return/parameter datatypes.  The first array element
	 * is the return datatype, which is followed by any input parameter datatypes in order.
	 * If addAutoParams is true, pointer datatypes will automatically be inserted for "this" or "hidden return"
	 * input parameters, if needed.  In this case, the dataTypes array should not include explicit entries for
	 * these parameters.  If addAutoParams is false, the dataTypes array is assumed to already contain explicit
	 * entries for any of these parameters.
	 * @param program is the Program
	 * @param dataTypes return/parameter datatypes (first element is always the return datatype, 
	 * i.e., minimum array length is 1)
	 * @param addAutoParams true if auto-parameter storage locations can be generated
	 * @return dynamic storage locations orders by ordinal where first element corresponds to
	 * return storage. The returned array may also include additional auto-parameter storage 
	 * locations. 
	 */
	public VariableStorage[] getStorageLocations(Program program, DataType[] dataTypes,
			boolean addAutoParams) {

		DataType injectedThis = null;
		if (addAutoParams && hasThis) {
			// explicit support for auto 'this' parameter
			// must inject pointer arg to obtain storage assignment
			injectedThis = new PointerDataType(program.getDataTypeManager());
		}
		PrototypePieces proto = new PrototypePieces(this, dataTypes, injectedThis);

		ArrayList<ParameterPieces> res = new ArrayList<>();
		assignParameterStorage(proto, program.getDataTypeManager(), res, addAutoParams);
		VariableStorage[] finalres = new VariableStorage[res.size()];

		for (int i = 0; i < finalres.length; ++i) {
			finalres[i] = res.get(i).getVariableStorage(program);
		}
		return finalres;
	}

	/**
	 * If this is an alias of another model, return that model.  Otherwise null is returned.
	 * @return the parent model or null
	 */
	public PrototypeModel getAliasParent() {
		return compatModel;
	}

	/**
	 * If a PrototypeModel fails to parse (from XML) a substitute model may be provided, in which
	 * case this method returns true.  In all other cases this method returns false;
	 * @return true if this object is a substitute for a model that didn't parse
	 */
	public boolean isErrorPlaceholder() {
		return false;
	}

	private void buildParamList(String strategy) throws XmlParseException {
		if (strategy == null || strategy.equals("standard")) {
			inputParams = new ParamListStandard();
			outputParams = new ParamListStandardOut();
			inputListType = InputListType.STANDARD;
		}
		else if (strategy.equals("register")) {
			inputParams = new ParamListStandard();
			outputParams = new ParamListRegisterOut();
			inputListType = InputListType.REGISTER;
		}
		else {
			throw new XmlParseException("Unknown assign strategy: " + strategy);
		}
	}

	/**
	 * Encode this object to an output stream
	 * @param encoder is the stream encoder
	 * @param injectLibrary is a library containing any inject payloads associated with the model
	 * @throws IOException for errors writing to the underlying stream
	 */
	public void encode(Encoder encoder, PcodeInjectLibrary injectLibrary) throws IOException {
		if (compatModel != null) {
			encoder.openElement(ELEM_MODELALIAS);
			encoder.writeString(ATTRIB_NAME, name);
			encoder.writeString(ATTRIB_PARENT, compatModel.name);
			encoder.closeElement(ELEM_MODELALIAS);
			return;
		}
		encoder.openElement(ELEM_PROTOTYPE);
		encoder.writeString(ATTRIB_NAME, name);
		if (extrapop != PrototypeModel.UNKNOWN_EXTRAPOP) {
			encoder.writeSignedInteger(ATTRIB_EXTRAPOP, extrapop);
		}
		else {
			encoder.writeString(ATTRIB_EXTRAPOP, "unknown");
		}
		encoder.writeSignedInteger(ATTRIB_STACKSHIFT, stackshift);
		if (hasThis) {
			encoder.writeBool(ATTRIB_HASTHIS, true);
		}
		if (isConstruct) {
			encoder.writeBool(ATTRIB_CONSTRUCTOR, true);
		}
		if (inputListType != InputListType.STANDARD) {
			encoder.writeString(ATTRIB_STRATEGY, "register");
		}
		inputParams.encode(encoder, true);
		outputParams.encode(encoder, false);
		if (hasUponEntry || hasUponReturn) {
			InjectPayload payload =
				injectLibrary.getPayload(InjectPayload.CALLMECHANISM_TYPE, getInjectName());
			payload.encode(encoder);
		}
		if (unaffected != null) {
			encoder.openElement(ELEM_UNAFFECTED);
			encodeVarnodes(encoder, unaffected);
			encoder.closeElement(ELEM_UNAFFECTED);
		}
		if (killedbycall != null) {
			encoder.openElement(ELEM_KILLEDBYCALL);
			encodeVarnodes(encoder, killedbycall);
			encoder.closeElement(ELEM_KILLEDBYCALL);
		}
		if (likelytrash != null) {
			encoder.openElement(ELEM_LIKELYTRASH);
			encodeVarnodes(encoder, likelytrash);
			encoder.closeElement(ELEM_LIKELYTRASH);
		}
		if (internalstorage != null) {
			encoder.openElement(ELEM_INTERNAL_STORAGE);
			encodeVarnodes(encoder, internalstorage);
			encoder.closeElement(ELEM_INTERNAL_STORAGE);
		}
		if (returnaddress != null) {
			encoder.openElement(ELEM_RETURNADDRESS);
			encodeVarnodes(encoder, returnaddress);
			encoder.closeElement(ELEM_RETURNADDRESS);
		}
		if (localRange != null && !localRange.isEmpty()) {
			encoder.openElement(ELEM_LOCALRANGE);
			encodeAddressSet(encoder, localRange);
			encoder.closeElement(ELEM_LOCALRANGE);
		}
		if (paramRange != null && !paramRange.isEmpty()) {
			encoder.openElement(ELEM_PARAMRANGE);
			encodeAddressSet(encoder, paramRange);
			encoder.closeElement(ELEM_PARAMRANGE);
		}
		encoder.closeElement(ELEM_PROTOTYPE);
	}

	private void encodeVarnodes(Encoder encoder, Varnode[] varnodes) throws IOException {
		for (Varnode vn : varnodes) {
			encoder.openElement(ELEM_VARNODE);
			AddressXML.encodeAttributes(encoder, vn.getAddress(), vn.getSize());
			encoder.closeElement(ELEM_VARNODE);
		}
	}

	private Varnode[] readVarnodes(XmlPullParser parser, CompilerSpec cspec)
			throws XmlParseException {
		parser.start();
		ArrayList<Varnode> varnodeList = new ArrayList<>();
		while (parser.peek().isStart()) {
			XmlElement el = parser.start();
			AddressXML ourAddress = AddressXML.restoreXml(el, cspec);
			if (ourAddress.getJoinRecord() != null) {
				throw new XmlParseException(
					"No \"join\" in <unaffected>, <killedbycall>, or <likelytrash>");
			}
			varnodeList.add(ourAddress.getVarnode());
			parser.end(el);
		}
		parser.end();
		Varnode[] res = new Varnode[varnodeList.size()];
		varnodeList.toArray(res);
		return res;
	}

	private void encodeAddressSet(Encoder encoder, AddressSet addressSet) throws IOException {
		AddressRangeIterator iter = addressSet.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange addrRange = iter.next();
			AddressSpace space = addrRange.getAddressSpace();
			long first = addrRange.getMinAddress().getOffset();
			long last = addrRange.getMaxAddress().getOffset();
			if (space.hasSignedOffset()) {
				long mask;
				if (space.getSize() < 64) {
					mask = 1;
					mask <<= space.getSize();
				}
				else {
					mask = 0;
				}
				mask -= 1;
				if (first < 0 && last >= 0) {	// Range crosses 0
					first &= mask;
					// Split out the piece coming before 0
					encoder.openElement(ELEM_RANGE);
					encoder.writeSpace(ATTRIB_SPACE, space);
					encoder.writeUnsignedInteger(ATTRIB_FIRST, first);
					encoder.writeUnsignedInteger(ATTRIB_LAST, mask);
					encoder.closeElement(ELEM_RANGE);
					// Reset first,last to be the piece coming after 0
					first = 0;
				}
				first &= mask;
				last &= mask;
			}
			encoder.openElement(ELEM_RANGE);
			encoder.writeSpace(ATTRIB_SPACE, space);
			encoder.writeUnsignedInteger(ATTRIB_FIRST, first);
			encoder.writeUnsignedInteger(ATTRIB_LAST, last);
			encoder.closeElement(ELEM_RANGE);
		}
	}

	private AddressSet readAddressSet(XmlPullParser parser, CompilerSpec cspec)
			throws XmlParseException {
		AddressSet addressSet = new AddressSet();
		parser.start();
		while (parser.peek().isStart()) {
			XmlElement el = parser.start();
			AddressXML range = AddressXML.restoreRangeXml(el, cspec);
			parser.end(el);
			Address firstAddr = range.getFirstAddress();
			Address lastAddr = range.getLastAddress();
			addressSet.add(firstAddr, lastAddr);
		}
		parser.end();
		return addressSet;
	}

	protected String getInjectName() {
		if (hasUponEntry) {
			return name + "@@inject_uponentry";
		}
		return name + "@@inject_uponreturn";
	}

	/**
	 * Restore the model from an XML stream.
	 * @param parser is the XML parser (initialized to the start of the stream)
	 * @param cspec is the parent compiler specification owning the model
	 * @throws XmlParseException is there are problems parsing the XML
	 */
	public void restoreXml(XmlPullParser parser, CompilerSpec cspec) throws XmlParseException {
		inputParams = null;
		outputParams = null;
		XmlElement protoElement = parser.start();
		name = protoElement.getAttribute("name");
		if (!SpecExtension.isValidFormalName(name)) {
			throw new XmlParseException("Prototype name uses illegal characters");
		}
		extrapop = PrototypeModel.UNKNOWN_EXTRAPOP;
		String extpopStr = protoElement.getAttribute("extrapop");
		if (!extpopStr.equals("unknown")) {
			extrapop = SpecXmlUtils.decodeInt(extpopStr);
		}
		stackshift = SpecXmlUtils.decodeInt(protoElement.getAttribute("stackshift"));
		hasThis = false;
		isConstruct = false;
		String thisString = protoElement.getAttribute("hasthis");
		if (thisString != null) {
			hasThis = SpecXmlUtils.decodeBoolean(thisString);
		}
		else {
			hasThis = name.equals(CompilerSpec.CALLING_CONVENTION_thiscall);
		}
		String constructString = protoElement.getAttribute("constructor");
		if (constructString != null) {
			isConstruct = SpecXmlUtils.decodeBoolean(constructString);
		}

		buildParamList(protoElement.getAttribute("strategy"));
		while (parser.peek().isStart()) {
			XmlElement subel = parser.peek();
			String elName = subel.getName();
			if (elName.equals("input")) {
				inputParams.restoreXml(parser, cspec);
			}
			else if (elName.equals("output")) {
				outputParams.restoreXml(parser, cspec);
			}
			else if (elName.equals("pcode")) {
				XmlElement el = parser.peek();
				String source = "Compiler spec=" + cspec.getCompilerSpecID().getIdAsString();
				if (el.getAttribute("inject").equals("uponentry")) {
					hasUponEntry = true;
				}
				else {
					hasUponReturn = true;
				}
				cspec.getPcodeInjectLibrary()
						.restoreXmlInject(source, getInjectName(), InjectPayload.CALLMECHANISM_TYPE,
							parser);
			}
			else if (elName.equals("unaffected")) {
				unaffected = readVarnodes(parser, cspec);
			}
			else if (elName.equals("killedbycall")) {
				killedbycall = readVarnodes(parser, cspec);
			}
			else if (elName.equals("returnaddress")) {
				returnaddress = readVarnodes(parser, cspec);
			}
			else if (elName.equals("likelytrash")) {
				likelytrash = readVarnodes(parser, cspec);
			}
			else if (elName.equals("internal_storage")) {
				internalstorage = readVarnodes(parser, cspec);
			}
			else if (elName.equals("localrange")) {
				localRange = readAddressSet(parser, cspec);
			}
			else if (elName.equals("paramrange")) {
				paramRange = readAddressSet(parser, cspec);
			}
			else {
				subel = parser.start();
				parser.discardSubTree(subel);
			}
		}
		parser.end(protoElement);
	}

	/**
	 * Determine if the given address range is possible input parameter storage for this model.
	 * If it is, "true" is returned, and additional information about the parameter's
	 * position is passed back in the provided record.
	 * @param loc is the starting address of the range
	 * @param size is the size of the range in bytes
	 * @param res is the pass-back record
	 * @return true if the range is a possible parameter
	 */
	public boolean possibleInputParamWithSlot(Address loc, int size, ParamList.WithSlotRec res) {
		return inputParams.possibleParamWithSlot(loc, size, res);
	}

	/**
	 * Determine if the given address range is possible return value storage for this model.
	 * If it is, "true" is returned, and additional information about the storage
	 * position is passed back in the provided record.
	 * @param loc is the starting address of the range
	 * @param size is the size of the range in bytes
	 * @param res is the pass-back record
	 * @return true if the range is possible return value storage
	 */
	public boolean possibleOutputParamWithSlot(Address loc, int size, ParamList.WithSlotRec res) {
		return outputParams.possibleParamWithSlot(loc, size, res);
	}

	/**
	 * Assuming the model allows open ended storage of parameters on the stack,
	 * return the byte alignment required for individual stack parameters.
	 * @return the stack alignment in bytes
	 */
	public int getStackParameterAlignment() {
		return inputParams.getStackParameterAlignment();
	}

	/**
	 * Return the byte offset where the first input parameter on the stack is allocated.
	 * The value is relative to the incoming stack pointer of the called function.
	 * For normal stacks, this is the offset of the first byte in the first parameter.
	 * For reverse stacks, this is the offset immediately after the last byte of the parameter.
	 * @return the byte offset of the first param
	 */
	public Long getStackParameterOffset() {
		return inputParams.getStackParameterOffset();
	}

	/**
	 * Get a list of all input storage locations consisting of a single register 
	 * @param prog is the current Program
	 * @return a VariableStorage ojbect for each register
	 */
	public VariableStorage[] getPotentialInputRegisterStorage(Program prog) {
		return inputParams.getPotentialRegisterStorage(prog);
	}

	/**
	 * Determine if this PrototypeModel is equivalent to another instance
	 * @param obj is the other instance
	 * @return true if they are equivalent
	 */
	public boolean isEquivalent(PrototypeModel obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		if (!name.equals(obj.name)) {
			return false;
		}
		if (extrapop != obj.extrapop || stackshift != obj.stackshift) {
			return false;
		}
		if (hasThis != obj.hasThis || isConstruct != obj.isConstruct) {
			return false;
		}
		if (hasUponEntry != obj.hasUponEntry || hasUponReturn != obj.hasUponReturn) {
			return false;
		}
		if (inputListType != obj.inputListType) {
			return false;
		}
		if (!inputParams.isEquivalent(obj.inputParams)) {
			return false;
		}
		if (!outputParams.isEquivalent(obj.outputParams)) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(unaffected, obj.unaffected)) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(killedbycall, obj.killedbycall)) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(likelytrash, obj.likelytrash)) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(internalstorage, obj.internalstorage)) {
			return false;
		}
		String compatName = (compatModel != null) ? compatModel.getName() : "";
		String compatNameOp2 = (obj.compatModel != null) ? obj.compatModel.getName() : "";
		if (!compatName.equals(compatNameOp2)) {
			return false;
		}
		if (!SystemUtilities.isEqual(localRange, obj.localRange)) {
			return false;
		}
		if (!SystemUtilities.isEqual(paramRange, obj.paramRange)) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(returnaddress, obj.returnaddress)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return getName();
	}

	/**
	 * Set the return address
	 * @param returnaddress return address
	 */
	protected void setReturnAddress(Varnode[] returnaddress) {
		this.returnaddress = returnaddress;
	}
}
