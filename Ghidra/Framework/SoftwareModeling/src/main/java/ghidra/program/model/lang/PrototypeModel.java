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

import java.util.ArrayList;

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.AddressXML;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * A function calling convention model.
 * Formal specification of how a compiler passes
 * arguments between functions.
 * 
 * 
 *
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
	private AddressSet localRange;	// Range on the stack considered for local storage
	private AddressSet paramRange;	// Range on the stack considered for parameter storage
	private InputListType inputListType = InputListType.STANDARD;
	private GenericCallingConvention genericCallingConvention;
	private boolean hasThis;		// Convention has a this (auto-parameter)
	private boolean isConstruct;		// Convention is used for object construction
	private boolean hasUponEntry;	// Does this have an uponentry injection
	private boolean hasUponReturn;	// Does this have an uponreturn injection

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
		localRange = new AddressSet(model.localRange);
		paramRange = new AddressSet(model.paramRange);
		hasThis = model.hasThis || name.equals(CompilerSpec.CALLING_CONVENTION_thiscall);
		isConstruct = model.isConstruct;
		genericCallingConvention = GenericCallingConvention.getGenericCallingConvention(name);
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
		localRange = null;
		paramRange = null;
		genericCallingConvention = GenericCallingConvention.unknown;
		hasThis = false;
		isConstruct = false;
		hasUponEntry = false;
		hasUponReturn = false;
	}

	public GenericCallingConvention getGenericCallingConvention() {
		return genericCallingConvention;
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
	 * @return list of registers/memory used to store the return address
	 */
	public Varnode[] getReturnAddress() {
		if (returnaddress == null) {
			returnaddress = new Varnode[0];
		}
		return returnaddress;
	}

	public boolean isMerged() {
		return false;
	}

	/**
	 * @return true if this model is a Program specific extension to the CompilerSpec
	 */
	public boolean isProgramExtension() {
		return isExtension;
	}

	public String getName() {
		return name;
	}

	public int getExtrapop() {
		return extrapop;
	}

	public int getStackshift() {
		return stackshift;
	}

	public boolean hasThisPointer() {
		return hasThis;
	}

	public boolean isConstructor() {
		return isConstruct;
	}

	public InputListType getInputListType() {
		return inputListType;
	}

	public boolean hasInjection() {
		return hasUponEntry || hasUponReturn;
	}

	/**
	 * @deprecated
	 * Get the preferred return location given the specified dataType.
	 * In truth, there is no one location.  The routines that use this method tend
	 * to want the default storage location for integer or pointer return values.
	 * @param dataType first parameter dataType or null for an undefined type.
	 * @param program is the Program
	 * @return return location or {@link VariableStorage#UNASSIGNED_STORAGE} if
	 * unable to determine suitable location
	 */
	@Deprecated
	public VariableStorage getReturnLocation(DataType dataType, Program program) {
		DataType clone = dataType.clone(program.getDataTypeManager());
		DataType[] arr = new DataType[1];
		arr[0] = clone;
		ArrayList<VariableStorage> res = new ArrayList<>();
		outputParams.assignMap(program, arr, res, false);
		if (res.size() > 0) {
			return res.get(0);
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
	 * Compute the variable storage for a given function and set of return/parameter datatypes 
	 * defined by an array of data types.
	 * @param program is the Program
	 * @param dataTypes return/parameter datatypes (first element is always the return datatype, 
	 * i.e., minimum array length is 1)
	 * @param addAutoParams TODO
	 * @return dynamic storage locations orders by ordinal where first element corresponds to
	 * return storage. The returned array may also include additional auto-parameter storage 
	 * locations. 
	 */
	public VariableStorage[] getStorageLocations(Program program, DataType[] dataTypes,
			boolean addAutoParams) {

		boolean injectAutoThisParam = false;
		if (addAutoParams && hasThis) {
			// explicit support for auto 'this' parameter
			// must inject pointer arg to obtain storage assignment
			injectAutoThisParam = true;
			DataType[] ammendedTypes = new DataType[dataTypes.length + 1];
			ammendedTypes[0] = dataTypes[0];
			ammendedTypes[1] = new PointerDataType(program.getDataTypeManager());
			if (dataTypes.length > 1) {
				System.arraycopy(dataTypes, 1, ammendedTypes, 2, dataTypes.length - 1);
			}
			dataTypes = ammendedTypes;
		}

		ArrayList<VariableStorage> res = new ArrayList<>();
		outputParams.assignMap(program, dataTypes, res, addAutoParams);
		inputParams.assignMap(program, dataTypes, res, addAutoParams);
		VariableStorage[] finalres = new VariableStorage[res.size()];
		res.toArray(finalres);

		if (injectAutoThisParam) {

			Varnode[] thisVarnodes = finalres[1].getVarnodes();

			int thisIndex = 1;
			try {
				if (finalres[1].isAutoStorage()) {
					if (inputParams.isThisBeforeRetPointer()) {
						// pointer has been bumped by auto-return-storage
						// must swap storage and position for slots 1 and 2 
						finalres[2] = new DynamicVariableStorage(program,
							finalres[1].getAutoParameterType(), finalres[2].getVarnodes());
					}
					else {
						thisIndex = 2;
						thisVarnodes = finalres[2].getVarnodes();
					}
				}

				if (thisVarnodes.length != 0) {
					finalres[thisIndex] =
						new DynamicVariableStorage(program, AutoParameterType.THIS, thisVarnodes);
				}
				else {
					finalres[thisIndex] =
						DynamicVariableStorage.getUnassignedDynamicStorage(AutoParameterType.THIS);
				}
			}
			catch (InvalidInputException e) {
				finalres[thisIndex] =
					DynamicVariableStorage.getUnassignedDynamicStorage(AutoParameterType.THIS);
			}

		}

		return finalres;
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

	public void saveXml(StringBuilder buffer, PcodeInjectLibrary injectLibrary) {
		buffer.append("<prototype");
		SpecXmlUtils.encodeStringAttribute(buffer, "name", name);
		if (extrapop != PrototypeModel.UNKNOWN_EXTRAPOP) {
			SpecXmlUtils.encodeSignedIntegerAttribute(buffer, "extrapop", extrapop);
		}
		else {
			SpecXmlUtils.encodeStringAttribute(buffer, "extrapop", "unknown");
		}
		SpecXmlUtils.encodeSignedIntegerAttribute(buffer, "stackshift", stackshift);
		GenericCallingConvention nameType = GenericCallingConvention.guessFromName(name);
		if (nameType != genericCallingConvention) {
			SpecXmlUtils.encodeStringAttribute(buffer, "type",
				genericCallingConvention.getDeclarationName());
		}
		if (hasThis) {
			SpecXmlUtils.encodeStringAttribute(buffer, "hasthis", "yes");
		}
		if (isConstruct) {
			SpecXmlUtils.encodeStringAttribute(buffer, "constructor", "yes");
		}
		if (inputListType != InputListType.STANDARD) {
			SpecXmlUtils.encodeStringAttribute(buffer, "strategy", "register");
		}
		buffer.append(">\n");
		inputParams.saveXml(buffer, true);
		buffer.append('\n');
		outputParams.saveXml(buffer, false);
		buffer.append('\n');
		if (hasUponEntry || hasUponReturn) {
			InjectPayload payload =
				injectLibrary.getPayload(InjectPayload.CALLMECHANISM_TYPE, getInjectName());
			payload.saveXml(buffer);
		}
		if (unaffected != null) {
			buffer.append("<unaffected>\n");
			writeVarnodes(buffer, unaffected);
			buffer.append("</unaffected>\n");
		}
		if (killedbycall != null) {
			buffer.append("<killedbycall>\n");
			writeVarnodes(buffer, killedbycall);
			buffer.append("</killedbycall>\n");
		}
		if (likelytrash != null) {
			buffer.append("<likelytrash>\n");
			writeVarnodes(buffer, likelytrash);
			buffer.append("</likelytrash>\n");
		}
		if (returnaddress != null) {
			buffer.append("<returnaddress>\n");
			writeVarnodes(buffer, returnaddress);
			buffer.append("</returnaddress>\n");
		}
		if (localRange != null && !localRange.isEmpty()) {
			buffer.append("<localrange>\n");
			writeAddressSet(buffer, localRange);
			buffer.append("</localrange>\n");
		}
		if (paramRange != null && !paramRange.isEmpty()) {
			buffer.append("<paramrange>\n");
			writeAddressSet(buffer, paramRange);
			buffer.append("</paramrange>\n");
		}
		buffer.append("</prototype>\n");
	}

	private void writeVarnodes(StringBuilder buffer, Varnode[] varnodes) {
		for (Varnode vn : varnodes) {
			buffer.append("<varnode");
			AddressXML.appendAttributes(buffer, vn.getAddress(), vn.getSize());
			buffer.append("/>\n");
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

	private void writeAddressSet(StringBuilder buffer, AddressSet addressSet) {
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
					buffer.append("<range");
					SpecXmlUtils.encodeStringAttribute(buffer, "space", space.getName());
					SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "first", first);
					SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "last", mask);
					buffer.append("/>\n");
					// Reset first,last to be the piece coming after 0
					first = 0;
				}
				first &= mask;
				last &= mask;
			}
			buffer.append("<range");
			SpecXmlUtils.encodeStringAttribute(buffer, "space", space.getName());
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "first", first);
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "last", last);
			buffer.append("/>\n");
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

	public void restoreXml(XmlPullParser parser, CompilerSpec cspec) throws XmlParseException {
		inputParams = null;
		outputParams = null;
		XmlElement protoElement = parser.start();
		name = protoElement.getAttribute("name");
		extrapop = PrototypeModel.UNKNOWN_EXTRAPOP;
		String extpopStr = protoElement.getAttribute("extrapop");
		if (!extpopStr.equals("unknown")) {
			extrapop = SpecXmlUtils.decodeInt(extpopStr);
		}
		stackshift = SpecXmlUtils.decodeInt(protoElement.getAttribute("stackshift"));
		String type = protoElement.getAttribute("type");
		if (type != null) {
			genericCallingConvention = GenericCallingConvention.getGenericCallingConvention(type);
		}
		else {
			genericCallingConvention = GenericCallingConvention.guessFromName(name);
		}
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

	public boolean possibleInputParamWithSlot(Address loc, int size, ParamList.WithSlotRec res) {
		return inputParams.possibleParamWithSlot(loc, size, res);
	}

	public boolean possibleOutputParamWithSlot(Address loc, int size, ParamList.WithSlotRec res) {
		return outputParams.possibleParamWithSlot(loc, size, res);
	}

	public int getStackParameterAlignment() {
		return inputParams.getStackParameterAlignment();
	}

	public Long getStackParameterOffset() {
		return inputParams.getStackParameterOffset();
	}

	public VariableStorage[] getPotentialInputRegisterStorage(Program prog) {
		return inputParams.getPotentialRegisterStorage(prog);
	}

	@Override
	public boolean equals(Object obj) {
		PrototypeModel op2 = (PrototypeModel) obj;
		if (!name.equals(op2.name)) {
			return false;
		}
		if (extrapop != op2.extrapop || stackshift != op2.stackshift) {
			return false;
		}
		if (genericCallingConvention != op2.genericCallingConvention) {
			return false;
		}
		if (hasThis != op2.hasThis || isConstruct != op2.isConstruct) {
			return false;
		}
		if (hasUponEntry != op2.hasUponEntry || hasUponReturn != op2.hasUponReturn) {
			return false;
		}
		if (inputListType != op2.inputListType) {
			return false;
		}
		if (!inputParams.equals(op2.inputParams)) {
			return false;
		}
		if (!outputParams.equals(op2.outputParams)) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(unaffected, op2.unaffected)) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(killedbycall, op2.killedbycall)) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(likelytrash, op2.likelytrash)) {
			return false;
		}
		if (!SystemUtilities.isEqual(localRange, op2.localRange)) {
			return false;
		}
		if (!SystemUtilities.isEqual(paramRange, op2.paramRange)) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(returnaddress, op2.returnaddress)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public String toString() {
		return getName();
	}
}
