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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
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
	private int extrapop; // change in stackpointer
	// across function calls
	private int stackshift; // change in stackpointer
	// due to call mechanism
	private ParamList inputParams; // (possible) parameter locations
	private ParamList outputParams;
	private InputListType inputListType = InputListType.STANDARD;
	private GenericCallingConvention genericCallingConvention;
	private boolean hasThis;		// Convention has a this (auto-parameter)
	private boolean isConstruct;		// Convention is used for object construction

	public PrototypeModel(String name, PrototypeModel model) {
		this.name = name;
		extrapop = model.extrapop;
		stackshift = model.stackshift;
		inputListType = model.inputListType;
		inputParams = model.inputParams;
		outputParams = model.outputParams;
		hasThis = model.hasThis || name.equals(CompilerSpec.CALLING_CONVENTION_thiscall);
		isConstruct = model.isConstruct;
		genericCallingConvention = GenericCallingConvention.getGenericCallingConvention(name);
	}

	public PrototypeModel() {
		name = null;
		extrapop = PrototypeModel.UNKNOWN_EXTRAPOP;
		stackshift = -1;
		inputParams = null;
		outputParams = null;
		genericCallingConvention = GenericCallingConvention.unknown;
		hasThis = false;
		isConstruct = false;
	}

	public GenericCallingConvention getGenericCallingConvention() {
		return genericCallingConvention;
	}

	public boolean isMerged() {
		return false;
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

	/**
	 * @deprecated
	 * Get the preferred return location given the specified dataType.
	 * In truth, there is no one location.  The routines that use this method tend
	 * to want the default storage location for integer or pointer return values.
	 * @param dataType first parameter dataType or null for a default
	 * undefined type.
	 * @param program
	 * @return return location or {@link VariableStorage#UNASSIGNED_STORAGE} if
	 * unable to determine suitable location
	 */
	@Deprecated
	public VariableStorage getReturnLocation(DataType dataType, Program program) {
		DataType clone = dataType.clone(program.getDataTypeManager());
		DataType[] arr = new DataType[1];
		arr[0] = clone;
		ArrayList<VariableStorage> res = new ArrayList<VariableStorage>();
		outputParams.assignMap(program, arr, false, res, false);
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
	 * @param program 
	 * @return next parameter location or {@link VariableStorage#UNASSIGNED_STORAGE} if
	 * unable to determine suitable location
	 */
	public VariableStorage getNextArgLocation(Parameter[] params, DataType dataType, Program program) {
		return getArgLocation(params != null ? params.length : 0, params, dataType, program);
	}

	/**
	 * Get the preferred parameter location for a specified parameter specified by argIndex
	 * which will be added/inserted within the set of existing function params.
	 * If existing parameters use custom storage, this method should not be used.
	 * @param params existing set parameters to which the parameter specified by
	 * argIndex will be added/inserted be appended (may be null).
	 * @param dataType dataType associated with next parameter location or null
	 * for a default undefined type.
	 * @param program 
	 * @return parameter location or {@link VariableStorage#UNASSIGNED_STORAGE} if
	 * unable to determine suitable location
	 */
	public VariableStorage getArgLocation(int argIndex, Parameter[] params, DataType dataType,
			Program program) {

		if (dataType != null)
			dataType = dataType.clone(program.getDataTypeManager());
		// Identify next arg index based upon number of storage varnodes 
		// already assigned to parameters - this may not work well if
		// customized storage has been used

		DataType arr[] = new DataType[argIndex + 2];
		arr[0] = DataType.VOID;				// Assume the return type is void
		for (int i = 0; i < argIndex; ++i) {
			if (params != null && i < params.length)
				arr[i + 1] = params[i].getDataType();			// Copy in current types if we have them
			else
				arr[i + 1] = DataType.DEFAULT;				// Otherwise assume default (integer) type
		}
		arr[argIndex + 1] = dataType;

		VariableStorage res[] = getStorageLocations(program, arr, false);
		return res[res.length - 1];
	}

	/**
	 * Compute the variable storage for a given function and set of return/parameter datatypes 
	 * defined by an array of data types.
	 * @param program
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

		ArrayList<VariableStorage> res = new ArrayList<VariableStorage>();
		outputParams.assignMap(program, dataTypes, false, res, addAutoParams);
		inputParams.assignMap(program, dataTypes, true, res, addAutoParams);
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
						finalres[2] =
							new DynamicVariableStorage(program, finalres[1].getAutoParameterType(),
								finalres[2].getVarnodes());
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
				finalres[thisIndex] = DynamicVariableStorage.getUnassignedDynamicStorage(AutoParameterType.THIS);
			}

		}

		return finalres;
	}

	private void buildParamList(String strategy) throws XmlParseException {
		if (strategy == null || strategy.equals("standard")) {
			inputParams = new ParamListStandard();
			outputParams = new ParamListStandardOut();
			inputListType = InputListType.STANDARD;
		}
		else if (strategy.equals("register")) {
			inputParams = new ParamListStandard();
			outputParams = new ParamListStandard();
			inputListType = InputListType.REGISTER;
		}
		else
			throw new XmlParseException("Unknown assign strategy: " + strategy);
	}

	public void restoreXml(XmlPullParser parser, CompilerSpec cspec, boolean normalstack)
			throws XmlParseException {
		inputParams = null;
		outputParams = null;
		XmlElement protoElement = parser.start();
		name = protoElement.getAttribute("name");
		extrapop = PrototypeModel.UNKNOWN_EXTRAPOP;
		String extpopStr = protoElement.getAttribute("extrapop");
		if (!extpopStr.equals("unknown"))
			extrapop = SpecXmlUtils.decodeInt(extpopStr);
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
		if (thisString != null)
			hasThis = SpecXmlUtils.decodeBoolean(thisString);
		else
			hasThis = name.equals(CompilerSpec.CALLING_CONVENTION_thiscall);
		String constructString = protoElement.getAttribute("constructor");
		if (constructString != null)
			isConstruct = SpecXmlUtils.decodeBoolean(constructString);

		buildParamList(protoElement.getAttribute("strategy"));
		while (parser.peek().isStart()) {
			XmlElement subel = parser.peek();
			if (subel.getName().equals("input")) {
				inputParams.restoreXml(parser, cspec, normalstack);
			}
			else if (subel.getName().equals("output")) {
				outputParams.restoreXml(parser, cspec, normalstack);
			}
			else if (subel.getName().equals("pcode")) {
				XmlElement el = parser.peek();
				String nm;
				String source = "Compiler spec=" + cspec.getCompilerSpecID().getIdAsString();
				if (el.getAttribute("inject").equals("uponentry"))
					nm = name + "@@inject_uponentry";
				else
					nm = name + "@@inject_uponreturn";
				cspec.getPcodeInjectLibrary().restoreXmlInject(source, nm,
					InjectPayload.CALLMECHANISM_TYPE, parser);
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
	public String toString() {
		return getName();
	}
}
