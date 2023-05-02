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
package ghidra.app.util.bin.format.dwarf4.next;

import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute.*;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.*;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.DataTypeNamingUtil;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFEndianity;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionException;
import ghidra.app.util.bin.format.golang.rtti.types.GoKind;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * Creates Ghidra {@link DataType}s using information from DWARF debug entries.  The caller
 * is responsible for writing the resulting temporary DataType instances into the database.
 * <p>
 * Create a new instance of this class for each {@link DIEAggregate} datatype that you wish
 * to convert into a DataType.
 * <p>
 */
public class DWARFDataTypeImporter {
	private DWARFProgram prog;
	private DataTypeManager dataTypeManager;
	private DWARFDataTypeManager dwarfDTM;
	private DWARFImportOptions importOptions;
	private DWARFDataType voidDDT;

	/**
	 * Tracks which {@link DIEAggregate DIEAs} have been visited by {@link #getDataTypeWorker(DIEAggregate, DataType)}
	 * during the current {@link #getDataType(DIEAggregate, DataType)} session.
	 * <p>
	 * Some recursive calls are permitted to handle loops in the data types, but are limited
	 * to 2 recursions.
	 */
	private Map<Long, Integer> recursionTrackingOffsetToLoopCount = new HashMap<>();

	/**
	 * Maps {@link DIEAggregate DIEA} offset to live {@link DataType} objects, for the
	 * current session of this importer.
	 */
	private Map<Long, DWARFDataType> dieOffsetToDataTypeMap = new HashMap<>();

	/**
	 * Maps {@link DataType} instances to the {@link DWARFDataType} record that
	 * holds metadata about this datatype during the current session.
	 * <p>
	 * This identity mapping doesn't always work because datatype instances are often clone()'d
	 * which will break this mapping.
	 * <p>
	 * Places where we know cloning happens the mapping is
	 * {@link #updateMapping(DataType, DataType) updated}.
	 */
	private IdentityHashMap<DataType, DWARFDataType> dataTypeInstanceToDDTMap =
		new IdentityHashMap<>();

	/**
	 * Create a new data type importer.
	 *
	 * @param prog {@link DWARFProgram} that is being imported
	 * @param dwarfDTM {@link DWARFDataTypeManager} helper
	 */
	public DWARFDataTypeImporter(DWARFProgram prog, DWARFDataTypeManager dwarfDTM) {
		this.prog = prog;
		this.dataTypeManager = prog.getGhidraProgram().getDataTypeManager();
		this.dwarfDTM = dwarfDTM;
		this.importOptions = prog.getImportOptions();
		this.voidDDT = new DWARFDataType(dwarfDTM.getVoidType(),
			DWARFNameInfo.fromDataType(dwarfDTM.getVoidType()), -1);
	}

	public DWARFDataType getDDTByInstance(DataType dtInstance) {
		return dataTypeInstanceToDDTMap.get(dtInstance);
	}

	private boolean trackRecursion(long id, int delta) {
		Integer count = recursionTrackingOffsetToLoopCount.getOrDefault(id, 0);
		count = count + delta;
		switch (count) {
			case 2:
				//Msg.warn(this, "Allowed recursive loop in datatype detected at " + id);
				break;
			case 3:
				Msg.error(this, "Recursive loop in datatype detected at " + Long.toHexString(id));
				return false;
		}
		recursionTrackingOffsetToLoopCount.put(id, count);
		return true;
	}

	/**
	 * Converts the specified DWARF debug entry into a Ghidra {@link DataType} (wrapped
	 * in a simple holder object to also return associated metadata).
	 *
	 * @param diea DWARF {@link DIEAggregate} to convert into Ghidra DataType.
	 * @param defaultValue value to return if the specified DIEA is null or there is a problem
	 * with the DWARF debug data.
	 * @return a {@link DWARFDataType} wrapper around the new Ghidra {@link DataType}.
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	public DWARFDataType getDataType(DIEAggregate diea, DWARFDataType defaultValue)
			throws IOException, DWARFExpressionException {

		if (diea == null) {
			return defaultValue;
		}

		// First try to find a datatype that has already been constructed for this DIEA and return
		// that if available.
		// Current impl (ie. not committed yet, this session only) datatypes are registered by offset->DDT.
		DWARFDataType result = dieOffsetToDataTypeMap.get(diea.getOffset());
		if (result != null) {
			return result;
		}

		// Query the dwarfDTM for plain Ghidra dataTypes that were previously
		// registered in a different import session.
		DataType alreadyImportedDT = dwarfDTM.getDataType(diea.getOffset(), null);
		if (shouldReuseAlreadyImportedDT(alreadyImportedDT)) {
			return new DWARFDataType(alreadyImportedDT, null, diea.getOffset());
		}

		if (!trackRecursion(diea.getOffset(), 1)) {
			return defaultValue;
		}

		// Fall back to creating a new Ghidra DataType from the info in the DIEA.
		switch (diea.getTag()) {
			case DW_TAG_pointer_type:
			case DW_TAG_reference_type:
			case DW_TAG_rvalue_reference_type:
				result = makeDataTypeForPointer(diea);
				break;
			case DW_TAG_ptr_to_member_type:
				result = makeDataTypeForPtrToMemberType(diea);
				break;
			case DW_TAG_base_type:
				result = makeDataTypeForBaseType(diea);
				break;
			case DW_TAG_typedef:
				result = makeDataTypeForTypedef(diea);
				break;
			case DW_TAG_unspecified_type:
				result = makeDataTypeForUnspecifiedType(diea);
				break;
			case DW_TAG_const_type:
			case DW_TAG_volatile_type:
			case DW_TAG_restrict_type:
			case DW_TAG_shared_type:
			case DW_TAG_APPLE_ptrauth_type:
				result = makeDataTypeForConst(diea);
				break;
			case DW_TAG_enumeration_type:
				result = makeDataTypeForEnum(diea);
				break;
			case DW_TAG_array_type:
				result = makeDataTypeForArray(diea);
				break;
			case DW_TAG_structure_type:
			case DW_TAG_class_type:
			case DW_TAG_union_type:
				result = makeDataTypeForStruct(diea);

				// push partial datatype info into currentTypes mapping to handle
				// recursion issues.
				recordTempDataType(result);

				finishStruct(diea, result);
				break;

			case DW_TAG_subroutine_type:
				result = makeDataTypeForFunctionDefinition(diea, true);
				break;
			case DW_TAG_subprogram:
				result = makeDataTypeForFunctionDefinition(diea, false);
				break;
			default:
				Msg.warn(this, "Unsupported datatype in die: " + diea.toString());
		}
		trackRecursion(diea.getOffset(), -1);

		if (result == null) {
			return defaultValue;
		}

		if (result.dsi == null) {
			result.dsi = DWARFSourceInfo.create(diea);
		}

		// store mapping info for this datatype for this session
		recordTempDataType(result);

		return result;
	}

	/**
	 * Returns true if the previously imported data type should be reused.
	 * <p>
	 * Don't re-use empty structs (isNotYetDefined) to ensure that newer
	 * definitions of the same struct are given a chance to be resolved() 
	 * into the DTM. 
	 * 
	 * @param alreadyImportedDT dataType to check
	 * @return boolean true if its okay to reuse the data type
	 */
	private boolean shouldReuseAlreadyImportedDT(DataType alreadyImportedDT) {
		return alreadyImportedDT != null && !alreadyImportedDT.isNotYetDefined();
	}

	/*
	 * when a clone()'d datatype is created, update the current mappings to
	 * point to the new instance instead of the old instance.
	 */
	private void updateMapping(DataType prevDT, DataType newDT) {
		DWARFDataType byPrevDT = dataTypeInstanceToDDTMap.get(prevDT);
		if (byPrevDT != null) {
			dataTypeInstanceToDDTMap.put(newDT, byPrevDT);
			byPrevDT.dataType = newDT;
		}
	}

	/*
	 * Record mapping data:  ddt_instance -> { offset_list }
	 * 						offset -> ddt
	 */
	private void recordTempDataType(DWARFDataType ddt) {
		if (ddt.dataType instanceof DatabaseObject) {
			// don't store info about types that are already in the database
			return;
		}
		dataTypeInstanceToDDTMap.put(ddt.dataType, ddt);
		for (Long offset : ddt.offsets) {
			dieOffsetToDataTypeMap.put(offset, ddt);
		}
	}

	/*
	 * Returns a Ghidra {@link FunctionDefinition} datatype built using the info from the DWARF die.
	 * <p>
	 * Function types may be assigned "mangled" names with parameter type info if the name
	 * is already used or if this is an unnamed function defintion.
	 * <p>
	 * Can accept DW_TAG_subprogram, DW_TAG_subroutine_type DIEAs.
	 * <p>
	 * The logic of this impl is the same as {@link DWARFDataTypeManager#createFunctionDefinitionDataType(DIEAggregate)}
	 * but the impls can't be shared without excessive over-engineering.
	 */
	private DWARFDataType makeDataTypeForFunctionDefinition(DIEAggregate diea,
			boolean mangleAnonFuncNames) throws IOException, DWARFExpressionException {

		DWARFNameInfo dni = prog.getName(diea);

		DWARFDataType returnType = getDataType(diea.getTypeRef(), voidDDT);

		boolean foundThisParam = false;
		List<ParameterDefinition> params = new ArrayList<>();
		for (DIEAggregate paramDIEA : diea.getFunctionParamList()) {

			String paramName = paramDIEA.getName();
			DWARFDataType paramDT = getDataType(paramDIEA.getTypeRef(), null);
			DataType dt = fixupDataTypeInconsistencies(paramDT);

			if (dt == null && DWARFUtil.isPointerDataType(paramDIEA.getTypeRef())) {
				// Hack to handle Golang self-referencing func defs.
				Msg.error(this,
					"Error resolving parameter data type, probable recursive definition, replacing with void*: " +
						dni.getName());
				Msg.debug(this, "Problem funcDef: " + diea.toString());
				Msg.debug(this, "Problem param: " + paramDIEA);
				dt = dwarfDTM.getPtrTo(dwarfDTM.getVoidType());
			}
			if (dt == null || dt.getLength() <= 0) {
				Msg.error(this, "Bad function parameter type for " + dni.asCategoryPath());
				return null;
			}

			ParameterDefinition pd = new ParameterDefinitionImpl(paramName, dt, null);
			params.add(pd);

			foundThisParam |= DWARFUtil.isThisParam(paramDIEA);
		}

		FunctionDefinitionDataType funcDef =
			new FunctionDefinitionDataType(dni.getParentCP(), dni.getName(), dataTypeManager);
		funcDef.setReturnType(returnType.dataType);
		funcDef.setNoReturn(diea.getBool(DW_AT_noreturn, false));
		funcDef.setArguments(params.toArray(new ParameterDefinition[params.size()]));

		if (!diea.getChildren(DW_TAG_unspecified_parameters).isEmpty()) {
			funcDef.setVarArgs(true);
		}

		if (foundThisParam) {
			try {
				funcDef.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Unexpected calling convention error", e);
			}
		}

		if (dni.isAnon() && mangleAnonFuncNames) {
			String mangledName =
				DataTypeNamingUtil.setMangledAnonymousFunctionName(funcDef);
			dni = dni.replaceName(mangledName, dni.getOriginalName());
		}

		for (int i = 0; i < funcDef.getArguments().length; i++) {
			ParameterDefinition origPD = params.get(i);
			ParameterDefinition newPD = funcDef.getArguments()[i];
			updateMapping(origPD.getDataType(), newPD.getDataType());
		}

		DataType dtToAdd = funcDef;
		if (diea.hasAttribute(DW_AT_byte_size)) {
			// if the funcdef has a bytesize attribute, we should convert this data type to a ptr
			long ptrSize = diea.getUnsignedLong(DW_AT_byte_size, -1);
			if (ptrSize == dataTypeManager.getDataOrganization().getPointerSize()) {
				ptrSize = -1;// use default pointer size
			}
			dtToAdd = dwarfDTM.getPtrTo(dtToAdd, (int) ptrSize);
		}

		return new DWARFDataType(dtToAdd, dni, diea.getOffset());
	}

	/**
	 * Gets the corresponding Ghidra base type.
	 * <p>
	 * @param diea
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	private DWARFDataType makeDataTypeForBaseType(DIEAggregate diea)
			throws IOException, DWARFExpressionException {

		return makeNamedBaseType(prog.getName(diea), diea);
	}

	private DWARFDataType makeNamedBaseType(DWARFNameInfo dni, DIEAggregate diea)
			throws IOException, DWARFExpressionException {
		int dwarfSize = diea.parseInt(DW_AT_byte_size, 0);
		int dwarfEncoding = (int) diea.getUnsignedLong(DW_AT_encoding, -1);
		boolean isBigEndian = DWARFEndianity.getEndianity(
			diea.getUnsignedLong(DW_AT_endianity, DWARFEndianity.DW_END_default),
			prog.isBigEndian());
		if (diea.hasAttribute(DW_AT_bit_size)) {
			Msg.warn(this,
				"Warning: Base type bit size and bit offset not currently handled for data type %s, DIE %s"
						.formatted(dni.toString(), diea.getHexOffset()));
		}
		boolean explictSize = false;
		if (diea.hasAttribute(DW_AT_go_kind)) {
			long goKindInt = diea.getLong(DW_AT_go_kind, 0);
			GoKind kind = GoKind.parseByte((byte) goKindInt);
			explictSize = isExplictSizedGolangType(kind);
		}

		DataType dt = dwarfDTM.getBaseType(dni.getOriginalName(), dwarfSize, dwarfEncoding,
			isBigEndian, explictSize);
		return new DWARFDataType(dt, dni, diea.getOffset());
	}

	private boolean isExplictSizedGolangType(GoKind kind) {
		switch (kind) {
			case Int8:
			case Int16:
			case Int32:
			case Int64:
			case Uint8:
			case Uint16:
			case Uint32:
			case Uint64:
			case Float32:
			case Float64:
			case Complex64:
			case Complex128:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Simple passthru, returns whatever type this "const" modifier applies to.
	 * <p>
	 * @param diea
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	private DWARFDataType makeDataTypeForConst(DIEAggregate diea)
			throws IOException, DWARFExpressionException {

		// Find the type the 'const' is applied to and transparently return it instead of ourselves.
		DWARFDataType refdDT = getDataType(diea.getTypeRef(), voidDDT);
		refdDT.offsets.add(diea.getOffset());

		return refdDT;
	}

	/**
	 * Creates a Ghidra {@link Enum} datatype.
	 * <p>
	 * If an existing Enum with the same name is found in the DTM, and it doesn't have
	 * any conflicting enum values, merge this enum into the existing enum.
	 * <p>
	 * This method takes liberties with the normal{@literal DWARF->Ghidra Impl DataType->Ghidra DB DataType}
	 * workflow to be able to merge values into previous db enum datatypes.
	 * <p>
	 *
	 * @param diea
	 * @return
	 */
	private DWARFDataType makeDataTypeForEnum(DIEAggregate diea) {

		DWARFNameInfo dni = prog.getName(diea);
		int enumSize = (int) diea.getUnsignedLong(DW_AT_byte_size, -1);
		// in addition to byte_size, enums can have encoding (signed/unsigned) and a basetype, which
		// itself might have a signed/unsigned encoding.
		// Which attributes are present varies wildly between versions and vendors, so seems 
		// best to just rely on the bare minimum.

		if (enumSize == 0) {
			Msg.warn(this, "Enum " + dni.getNamespacePath() + "[DWARF DIE " + diea.getHexOffset() +
				"] has a size of 0, forcing to 1");
			enumSize = 1;
		}
		if (enumSize == -1) {
			Msg.warn(this, "Enum " + dni.getNamespacePath() + "[DWARF DIE " + diea.getHexOffset() +
				"] does not have a size specified, forcing to 1");
			enumSize = 1;
		}

		Enum enumDT = new EnumDataType(dni.getParentCP(), dni.getName(), enumSize, dataTypeManager);
		populateStubEnum(enumDT, diea, false);

		// Merge enums with the same name / category path if possible
		for (DataType prevDT : dwarfDTM.forAllConflicts(dni.asDataTypePath())) {
			if (prevDT instanceof Enum prevEnum && prevEnum.getLength() == enumDT.getLength()) {
				if (isCompatEnumValues(enumDT, prevEnum)) {
					mergeEnumValues(prevEnum, enumDT);
					return new DWARFDataType(prevEnum, dni, diea.getOffset());
				}
			}
		}

		DataType result =
			dataTypeManager.addDataType(enumDT, DWARFDataTypeConflictHandler.INSTANCE);

		return new DWARFDataType(result, dni, diea.getOffset());
	}

	private void populateStubEnum(Enum enumDT, DIEAggregate diea, boolean defaultSignedness) {
		// NOTE: gcc tends to emit values without an explicit signedness.  The caller
		// can specify a default signedness, but this should probably always be unsigned.
		for (DebugInfoEntry childEntry : diea.getChildren(DW_TAG_enumerator)) {
			DIEAggregate childDIEA = prog.getAggregate(childEntry);
			String valueName = childDIEA.getName();

			DWARFNumericAttribute enumValAttr = childDIEA
					.getAttribute(DW_AT_const_value, DWARFNumericAttribute.class);
			if (enumValAttr != null) {
				long enumVal = enumValAttr.getValueWithSignednessHint(defaultSignedness);

				// NOTE: adding the same name=value pair a second time is handled correctly and ignored.
				// Adding a second name=different_value pair generates an exception
				try {
					enumDT.add(valueName, enumVal);
				}
				catch (IllegalArgumentException iae) {
					Msg.error(this,
						"Failed to add value %s=%d[%x] to enum %s".formatted(valueName, enumVal,
							enumVal, enumDT.getCategoryPath()),
						iae);
				}
			}
		}
	}

	private boolean mergeEnumValues(Enum destEnum, Enum srcEnum) {
		for (String srcKey : srcEnum.getNames()) {
			long srcValue = srcEnum.getValue(srcKey);

			try {
				long destValue = destEnum.getValue(srcKey);
				if (destValue == srcValue) {
					// key=value already exists, skip
					continue;
				}

				// the key exists but has a different value and the merge should fail
				return false;
			}
			catch (NoSuchElementException nse) {

				// good, we don't want the destEnum to have the key.
				// add the key to the destEnum
				try {
					destEnum.add(srcKey, srcValue);
				}
				catch (IllegalArgumentException iae) {
					// there was a conflict, fail the merge
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Returns true if there are no values in destEnum that conflict with srcEnum.
	 *
	 * @param srcEnum
	 * @param destEnum
	 * @return
	 */
	private boolean isCompatEnumValues(Enum srcEnum, Enum destEnum) {
		for (String srcKey : srcEnum.getNames()) {
			long srcValue = srcEnum.getValue(srcKey);

			try {
				long destValue = destEnum.getValue(srcKey);
				if (destValue != srcValue) {
					return false;
				}
			}
			catch (NoSuchElementException nse) {
				// missing element is good
			}
		}
		return true;
	}

	/**
	 * Creates an empty stub structure/union for the DIEA.
	 * <p>
	 * Use {@link #finishStruct(DIEAggregate, DataType)} (which calls
	 * {@link #populateStubStruct(StructureDataType, DIEAggregate)} and
	 * {@link #populateStubEnum(Enum, DIEAggregate)}) to fill in the fields of the structure.
	 * <p>
	 * This is done in two steps to enable ending recursive loops by publishing the empty
	 * struct in the {@link #dieOffsetToDataTypeMap} map, where it will be found and returned by
	 * {@link #getDataTypeWorker(DIEAggregate, DataType)}, instead of calling back
	 * into this method.
	 * @param diea
	 * @return
	 */
	private DWARFDataType makeDataTypeForStruct(DIEAggregate diea) {

		DWARFNameInfo dni = prog.getName(diea);

		long structSize = diea.getUnsignedLong(DW_AT_byte_size, 0);
		long origStructSize = structSize;
		if (isStructTooBigForGhidra(structSize)) {
			Msg.error(this, "Large DWARF structure encountered, substituting empty struct for " +
				dni + ", size: " + Long.toString(structSize) + " at DIE " + diea.getHexOffset());
			structSize = 0;
		}
		boolean isUnion = diea.getTag() == DW_TAG_union_type;
		boolean isDecl = diea.getBool(DW_AT_declaration, false);

		DataType struct =
			isUnion ? new UnionDataType(dni.getParentCP(), dni.getName(), dataTypeManager)
					: new StructureDataType(dni.getParentCP(), dni.getName(), (int) structSize,
						dataTypeManager);

		if (!isDecl && origStructSize == 0) {
			// Enable packing on 0-byte composites so they are treated as defined
			// and will not take space if used in a field in another composite.
			((Composite) struct).setToDefaultPacking();
		}

		DWARFDataType result = new DWARFDataType(struct, dni, diea.getOffset());
		result.dsi = DWARFSourceInfo.create(diea);

		if (dni.isNameModified() && !dni.isAnon()) {
			DWARFUtil.appendDescription(struct, "Original name: " + dni.getOriginalName(), "\n");
		}

		if (importOptions.isOutputDIEInfo()) {
			DWARFUtil.appendDescription(struct, "DWARF DIE: " + diea.getHexOffset(), "\n");
		}

		if (importOptions.isOutputSourceLocationInfo() && result.dsi != null &&
			result.dsi.getDescriptionStr() != null) {
			DWARFUtil.appendDescription(struct, result.dsi.getDescriptionStr(), "\n");
		}

		if (isStructTooBigForGhidra(origStructSize)) {
			DWARFUtil.appendDescription(struct,
				"Structure oversize error, original size: " + Long.toString(origStructSize), "\n");
		}

		return result;
	}

	/**
	 * Returns true if the DWARF struct is larger than Ghidra allows (ie. bigger than MAX_INT).
	 *
	 * @param structSize long int size of the DWARF struct
	 * @return true if bigger than Ghidra can handle
	 */
	private boolean isStructTooBigForGhidra(long structSize) {
		return (structSize < 0 || structSize > Integer.MAX_VALUE);
	}

	/**
	 * Populates stub structs or unions with there fields.
	 * @param diea
	 * @param dataType
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	private void finishStruct(DIEAggregate diea, DWARFDataType ddt)
			throws IOException, DWARFExpressionException {

		if (ddt.dataType instanceof UnionDataType) {
			populateStubUnion(ddt, diea);
		}
		else if (ddt.dataType instanceof StructureDataType) {
			populateStubStruct(ddt, diea);
		}
		else {
			throw new RuntimeException("bad datatype");
		}
	}

	/**
	 * Populates an empty {@link UnionDataType} with its fields.
	 * @param union
	 * @param diea
	 * @param rec
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	private void populateStubUnion(DWARFDataType ddt, DIEAggregate diea)
			throws IOException, DWARFExpressionException {
		long unionSize = diea.getUnsignedLong(DW_AT_byte_size, -1);

		UnionDataType union = (UnionDataType) ddt.dataType;
		for (DebugInfoEntry childEntry : diea.getChildren(DW_TAG_member)) {
			DIEAggregate childDIEA = prog.getAggregate(childEntry);

			// skip static member vars as they do not have storage in the structure
			// C does not allow static member vars in unions
			if (childDIEA.hasAttribute(DW_AT_external)) {
				continue;
			}

			int bitSize = childDIEA.parseInt(DW_AT_bit_size, -1);
			boolean isBitField = bitSize != -1;

			String memberName = childDIEA.getName();
			if (memberName == null) {
				memberName = "field_" + union.getNumComponents();
			}

			DWARFDataType childDT = getDataType(childDIEA.getTypeRef(), null);
			if (childDT == null) {
				Msg.warn(this, "Bad union member data type for " + memberName + " in " +
					union.getDataTypePath() + "[DWARF DIE " + diea.getHexOffset() + "], skipping");
				continue;
			}

			DataType dt = fixupDataTypeInconsistencies(childDT);
			String memberComment = null;
			if (dt instanceof Dynamic ||
				dt instanceof FactoryDataType) {
				memberComment = "Unsupported dynamic size data type: " + dt;
				dt = Undefined.getUndefinedDataType(1);
			}
			int dtLen = dt.getLength();
			if (unionSize != -1 && !isBitField && dtLen > unionSize) {
				// if we can, ensure that the member being added to the union isn't larger
				// than what DWARF specifies.

				if (dtLen > 1) {
					// replace problematic datatype with 1 byte undefined placeholder
					memberComment =
						"Data type larger than union's declared size: " + dt;
					dt = Undefined.getUndefinedDataType(1);
				}
				else {
					// can't do any fancy replacement, just add warning to union's description
					DWARFUtil.appendDescription(union, memberDesc("Missing member",
						"data type larger than union", memberName, dt, -1, bitSize, -1), "\n");
					continue;
				}
			}

			if (isBitField) {
				if (!BitFieldDataType.isValidBaseDataType(dt)) {
					DWARFUtil.appendDescription(union,
						memberDesc("Missing member",
							"Bad data type for bitfield: " + dt.getName(), memberName,
							dt, -1, bitSize, -1),
						"\n");
					continue;
				}

				// DWARF has attributes (DWARFAttribute.DW_AT_data_bit_offset, DWARFAttribute.DW_AT_bit_offset)
				// that specify the bit_offset of the field in the union.  We don't use them.
				try {
					union.addBitField(dt, bitSize, memberName, memberComment);
				}
				catch (InvalidDataTypeException e) {
					Msg.error(this,
						"Unable to add member " + memberName + " to structure " +
							union.getDataTypePath() + "[DWARF DIE " + diea.getHexOffset() +
							"], skipping: " + e.getMessage());
					DWARFUtil.appendDescription(union, memberDesc("Missing member ",
						"Failed to add bitfield", memberName, dt, -1, bitSize, -1), "\n");
				}
			}
			else {
				// just a normal field
				try {
					DataTypeComponent dataTypeComponent =
						union.add(dt, memberName, memberComment);
					// adding a member to a composite can cause a clone() of the datatype instance, so
					// update the instance mapping to keep track of the new instance.
					updateMapping(dt, dataTypeComponent.getDataType());
				}
				catch (IllegalArgumentException exc) {
					Msg.error(this,
						"Bad union member " + memberName + " in " + union.getDataTypePath() +
							"[DWARF DIE " + diea.getHexOffset() + "] of type " + childDT +
							", skipping");
				}
			}
		}

		if (union.getLength() < unionSize) {
			// NOTE: this is likely due incorrect alignment for union or one or more of its components.
			// Default alignment is 1 for non-packed unions and structures.

			// if the Ghidra union data type is smaller than the DWARF union, pad it out
			DataType padding = Undefined.getUndefinedDataType((int) unionSize);
			try {
				union.add(padding, null,
					"Automatically generated padding to match DWARF declared size");
			}
			catch (IllegalArgumentException exc) {
				DWARFUtil.appendDescription(union,
					"Failed to add padding to union, size should be " + unionSize, "\n");
			}
		}
		if (unionSize > 0 && union.getLength() > unionSize) {
			DWARFUtil.appendDescription(union, "Imported union size (" + union.getLength() +
				") is larger than DWARF value (" + unionSize + ")", "\n");
		}
		if (importOptions.isTryPackStructs()) {
			DWARFUtil.packCompositeIfPossible((Composite) ddt.dataType, dataTypeManager);
		}
	}

	/**
	 * Populates an empty {@link StructureDataType} with its fields.
	 * @param structure
	 * @param diea
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	private void populateStubStruct(DWARFDataType ddt, DIEAggregate diea)
			throws IOException, DWARFExpressionException {

		StructureDataType structure = (StructureDataType) ddt.dataType;

		long structSize = diea.getUnsignedLong(DW_AT_byte_size, 0);
		if (isStructTooBigForGhidra(structSize)) {
			return;
		}

		// Add member fields first before inheritance because empty base classes' offset
		// location can conflict with the first member field's offset.
		// This means that member fields will be successfully added and the field
		// that represents the base class will fail in these cases.
		populateStubStruct_worker(ddt, structure, diea, DW_TAG_member);
		populateStubStruct_worker(ddt, structure, diea, DW_TAG_inheritance);
		removeUneededStructMemberShrinkage(structure);
		if (importOptions.isTryPackStructs()) {
			DWARFUtil.packCompositeIfPossible((Composite) ddt.dataType, dataTypeManager);
		}
	}

	/**
	 * Restore structure fields to their regular size (if there is room) to ensure
	 * future DataType equiv and comparisons are successful.
	 * <p>
	 * (ie. undoes {@link #getUnpaddedDataTypeLength(DataType)} if there is room)
	 * @param structure
	 */
	private void removeUneededStructMemberShrinkage(StructureDataType structure) {
		DataTypeComponent[] definedComponents = structure.getDefinedComponents();
		for (int i = 0; i < definedComponents.length; i++) {
			DataTypeComponent dtc = definedComponents[i];
			DataType dtcDT = dtc.getDataType();
			if (dtcDT.isZeroLength()) {
				continue;
			}
			int nextDTCOffset =
				(i < definedComponents.length - 1) ? definedComponents[i + 1].getOffset()
						: structure.getLength();
			int emptySpaceBetween = nextDTCOffset - (dtc.getEndOffset() + 1);
			if (dtc.getLength() < dtcDT.getLength() && emptySpaceBetween > 0) {
				DataTypeComponent newDTC = structure.replaceAtOffset(dtc.getOffset(), dtcDT,
					Math.min(nextDTCOffset - dtc.getOffset(), dtc.getDataType().getLength()),
					dtc.getFieldName(), dtc.getComment());
				DataType newDT = newDTC.getDataType();
				if (newDT != dtcDT) {
					updateMapping(dtcDT, newDT);
				}
			}
		}

	}

	/**
	 * Detect the real length of a DataType (ie. drop any trailing padding).
	 * @param dt
	 * @return
	 */
	private int getUnpaddedDataTypeLength(DataType dt) {
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (dt instanceof Structure) {
			Structure structure = (Structure) dt;
			DataTypeComponent[] definedComponents = structure.getDefinedComponents();
			if (definedComponents.length > 0) {
				DataTypeComponent lastDTC = definedComponents[definedComponents.length - 1];
				return lastDTC.getOffset() + lastDTC.getLength();
			}
		}
		return dt.isZeroLength() ? 0 : dt.getLength();
	}

	private void populateStubStruct_worker(DWARFDataType ddt, StructureDataType structure,
			DIEAggregate diea, int childTagType) throws IOException, DWARFExpressionException {

		for (DebugInfoEntry childEntry : diea.getChildren(childTagType)) {

			DIEAggregate childDIEA = prog.getAggregate(childEntry);
			// skip static member vars as they do not have storage in the structure
			if (childDIEA.hasAttribute(DW_AT_external)) {
				continue;
			}

			int bitSize = childDIEA.parseInt(DW_AT_bit_size, -1);
			boolean isBitField = bitSize != -1;

			DWARFDataType childDT = getDataType(childDIEA.getTypeRef(), null);
			if (childDT == null) {
				Msg.error(this,
					"Failed to get data type for struct field: " + childDIEA.getHexOffset());
				continue;
			}
			DataType dt = fixupDataTypeInconsistencies(childDT);

			String memberName = childDIEA.getName();

			// construct a name for the member if needed using context information
			// instead of relying on DNI
			if (memberName == null) {
				// If the member is an inheritance type, then set the name
				// to be the name of the data type
				if (childDIEA.getTag() == DW_TAG_inheritance) {
					memberName = "super_" + dt.getName();
				}
				else {
					memberName = "field_" + structure.getNumDefinedComponents();
				}
			}

			boolean hasMemberOffset =
				childDIEA.hasAttribute(DW_AT_data_member_location);

			int memberOffset = 0;
			if (hasMemberOffset) {
				try {
					memberOffset = childDIEA.parseDataMemberOffset(DW_AT_data_member_location, 0);
				}
				catch (DWARFExpressionException e) {
					DWARFUtil.appendDescription(structure, memberDesc("Missing member",
						"failed to parse location", memberName, dt, -1, bitSize, -1), "\n");
					continue;
				}
			}

			//if (childDT.getPathName().equals(structure.getPathName()) && childDT != structure) {
			// The child we are adding has the exact same fullpath as us.
			// This can happen when DWARF namespace info gets squished and two types
			// originally from different namespaces with the same name end up in the root namespace.
			// Even though we aren't doing anything yet, with more data or examples
			// we will probably decide that this needs to be addressed in the future.
			// TODO: rename parent struct here.  use .conflict or _basetype?
			//}

			if (isBitField) {
				if (!BitFieldDataType.isValidBaseDataType(dt)) {
					DWARFUtil.appendDescription(structure,
						memberDesc("Missing member", "Bad data type for bitfield: " + dt.getName(),
							memberName, dt, -1, bitSize, -1),
						"\n");
					continue;
				}

				int containerLen;
				if (hasMemberOffset) {
					int byteSize = childDIEA.parseInt(DW_AT_byte_size, -1);
					containerLen = byteSize <= 0 ? dt.getLength() : byteSize;
				}
				else {
					containerLen = structure.getLength();
				}
				int containerBitLen = containerLen * 8;

				int bitOffset = childDIEA.parseInt(DW_AT_data_bit_offset, -1);
				int ghidraBitOffset;
				if (bitOffset == -1) {
					// try to fall back to previous dwarf version's bit_offset attribute that has slightly different info
					bitOffset = childDIEA.parseInt(DW_AT_bit_offset, -1);

					// convert DWARF bit offset value to Ghidra bit offset
					ghidraBitOffset = containerBitLen - bitOffset - bitSize;
				}
				else {
					// convert DWARF bit offset to Ghidra bit offset
					ghidraBitOffset = bitOffset - (memberOffset * 8);
					boolean isBE = prog.getGhidraProgram().getMemory().isBigEndian();
					if (isBE) {
						ghidraBitOffset = containerBitLen - ghidraBitOffset - bitSize;
					}
				}

				if (bitOffset < 0 || ghidraBitOffset < 0 || ghidraBitOffset >= containerBitLen) {
					DWARFUtil.appendDescription(structure, memberDesc("Missing member",
						"bad bitOffset", memberName, dt, memberOffset, bitSize, bitOffset),
						"\n");
					continue;
				}

				try {
					// TODO: need safety checks here to make sure that using insertAt() doesn't
					// modify the struct
					structure.insertBitFieldAt(memberOffset, containerLen, ghidraBitOffset,
						dt, bitSize, memberName, null);
				}
				catch (InvalidDataTypeException e) {
					Msg.error(this,
						"Unable to add member " + memberName + " to structure " +
							structure.getDataTypePath() + "[DWARF DIE " + diea.getHexOffset() +
							"], skipping: " + e.getMessage());
					DWARFUtil.appendDescription(structure,
						memberDesc("Missing member ", "Failed to add bitfield", memberName, dt,
							memberOffset, bitSize, bitOffset),
						"\n");
				}
			}
			else {
				String memberComment = null;
				boolean isDynamicSizedType =
					(dt instanceof Dynamic || dt instanceof FactoryDataType);
				if (isDynamicSizedType) {
					memberComment = "Unsupported dynamic size data type: " + dt;
					dt = Undefined.getUndefinedDataType(1);
				}
				int childLength = getUnpaddedDataTypeLength(dt);
				if (memberOffset + childLength > structure.getLength()) {
					DWARFUtil.appendDescription(structure, memberDesc("Missing member",
						"exceeds parent struct len", memberName, dt, memberOffset, -1, -1),
						"\n");

					continue;
				}

				try {
					DataTypeComponent dtc;
					if (DataTypeComponent.usesZeroLengthComponent(dt)) {
						if (!isUndefinedOrZeroLenAtOffset(structure, memberOffset)) {
							DWARFUtil.appendDescription(structure, memberDesc("Missing member",
								"conflicting member at same offset", memberName, dt,
								memberOffset, -1, -1), "\n");
							continue;
						}
						// use insertAt for zero len members to allow multiple at same offset
						dtc =
							structure.insertAtOffset(memberOffset, dt, 0, memberName,
								memberComment);
					}
					else {
						int ordinalToReplace = getUndefinedOrdinalAt(structure, memberOffset);
						if (ordinalToReplace == -1) {
							DataTypeComponent existingDTC =
								structure.getComponentContaining(memberOffset);
							if (existingDTC != null) {
								DWARFUtil.appendDescription(structure,
									memberDesc("Missing member",
										"conflict with " + existingDTC.getFieldName(),
										memberName, dt, memberOffset, -1, -1),
									"\n");
							}
							continue;
						}
						dtc = structure.replace(ordinalToReplace, dt, childLength, memberName,
							memberComment);
					}
					// struct.replaceAtOffset() and insertAtOffset() clones the childDT, which will mess up our
					// identity based mapping in currentImplDataTypeToDDT.
					// Update the mapping to prevent that.
					updateMapping(dt, dtc.getDataType());
				}
				catch (IllegalArgumentException exc) {
					Msg.error(this,
						"Unable to add member " + memberName + " to structure " +
							structure.getDataTypePath() + "[DWARF DIE " + diea.getHexOffset() +
							"], skipping: " + exc.getMessage());
					DWARFUtil.appendDescription(structure, memberDesc("Missing member ", "",
						memberName, dt, memberOffset, -1, -1), "\n");
				}
			}
		}
	}

	private boolean isUndefinedOrZeroLenAtOffset(Structure struct, int offset) {
		List<DataTypeComponent> compsAt = struct.getComponentsContaining(offset);
		DataTypeComponent lastComp = !compsAt.isEmpty() ? compsAt.get(compsAt.size() - 1) : null;
		if (lastComp == null) {
			// only triggered if offset == length of struct, which is okay since we are adding
			// a zero-length component to the struct
			return true;
		}
		if (lastComp.getOffset() != offset) {
			return false;
		}
		DataType dt = lastComp.getDataType();
		return dt.isZeroLength() || dt instanceof DefaultDataType;
	}

	private int getUndefinedOrdinalAt(Structure struct, int offset) {
		List<DataTypeComponent> compsAt = struct.getComponentsContaining(offset);
		DataTypeComponent lastComp = !compsAt.isEmpty() ? compsAt.get(compsAt.size() - 1) : null;
		if (lastComp == null || lastComp.getOffset() != offset ||
			!(lastComp.getDataType() instanceof DefaultDataType)) {
			return -1;
		}
		return lastComp.getOrdinal();
	}

	private static String memberDesc(String prefix, String errorStr, String memberName,
			DataType dt, int memberOffset, int bitSize, int bitOffset) {
		return (!StringUtils.isBlank(prefix) ? prefix + " " : "") + memberName + " : " +
			dt.getName() + (bitSize != -1 ? ":" + bitSize : "") + " at offset " +
			(memberOffset != -1 ? "0x" + Long.toHexString(memberOffset) : "unknown") +
			(bitOffset != -1 ? ":" + bitOffset : "") +
			(!StringUtils.isBlank(errorStr) ? " [" + errorStr + "]" : "");
	}

	private DataType fixupDataTypeInconsistencies(DWARFDataType ddt) {
		if (ddt == null) {
			return null;
		}
		DataType result = ddt.dataType;
		if (result instanceof FunctionDefinition) {
			result = dwarfDTM.getPtrTo(result);
		}
		return result;
	}

	/**
	 * Creates a Ghidra {@link ArrayDataType}.
	 * <p>
	 * Multi-dim DWARF arrays will result in nested Ghidra array types.
	 * <p>
	 * @param diea
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	private DWARFDataType makeDataTypeForArray(DIEAggregate diea)
			throws IOException, DWARFExpressionException {

		DWARFDataType elementType = getDataType(diea.getTypeRef(), voidDDT);
		// do a second query to see if there was a recursive loop in the call above back
		// to this datatype that resulted in this datatype being created.
		// Use that instance if possible.
		DWARFDataType self = dieOffsetToDataTypeMap.get(diea.getOffset());
		if (self != null) {
			return self;
		}
		DataType elementDT = fixupDataTypeInconsistencies(elementType);

		long explictArraySize = diea.getUnsignedLong(DW_AT_byte_size, -1);
		if (elementType.dataType.isZeroLength() || explictArraySize == 0) {
			// don't bother checking range info, we are going to force a zero-element array
			DataType zeroLenArray = new ArrayDataType(elementDT, 0, -1, dataTypeManager);
			return new DWARFDataType(zeroLenArray, null, diea.getOffset());
		}

		// Build a list of the defined dimensions for this array type.
		// The first element in the DWARF dimension list would be where a wild-card (-1 length)
		// dimension would be defined.
		List<Integer> dimensions = new ArrayList<>();
		List<DebugInfoEntry> subrangeDIEs = diea.getChildren(DW_TAG_subrange_type);
		for (int subRangeDIEIndex = 0; subRangeDIEIndex < subrangeDIEs.size(); subRangeDIEIndex++) {
			DIEAggregate subrangeAggr = prog.getAggregate(subrangeDIEs.get(subRangeDIEIndex));
			long numElements = -1;
			try {
				if (subrangeAggr.hasAttribute(DW_AT_count)) {
					numElements =
						subrangeAggr.parseUnsignedLong(DW_AT_count, 0xbadbeef);
				}
				// Otherwise check for an upper bound
				else if (subrangeAggr.hasAttribute(DW_AT_upper_bound)) {
					long upperBound =
						subrangeAggr.parseUnsignedLong(DW_AT_upper_bound, 0xbadbeef);

					// fix special flag values used by DWARF to indicate that the array dimension
					// is unknown.  64bit 0xffffff...s and 32bit 0xffff..s will
					// be forced to 0.
					if (upperBound == 0xFF_FF_FF_FFL /* ie. max uint32 */ || upperBound == -1) {
						upperBound = 0;
					}
					else {
						numElements = upperBound + 1;
					}
				}
			}
			catch (UnsupportedOperationException | IOException | IndexOutOfBoundsException
					| DWARFExpressionException e) {
				// ignore
			}

			if (numElements == -1) {
				numElements = 0;
			}
			else if (numElements > Integer.MAX_VALUE) {
				Msg.error(this, "Bad value [" + numElements + "] for array's size in DIE: " +
					diea.getHexOffset() + ", forcing to 1");
				numElements = 1;
			}

			dimensions.add((int) numElements);
		}

		DataType dt = elementDT;
		for (int i = dimensions.size() - 1; i >= 0; i--) {
			int numElements = dimensions.get(i);
			ArrayDataType subArray =
				new ArrayDataType(dt, numElements, -1, dataTypeManager);
			if (dt == elementDT) {
				updateMapping(dt, subArray.getDataType());
			}
			dt = subArray;
		}

		DWARFDataType result = new DWARFDataType(dt, null, diea.getOffset());

		return result;
	}

	/**
	 * Creates a {@link Pointer} datatype.
	 * <p>
	 * If there is no pointer size specified in the DWARF DIE, use the default pointer size
	 * from the DWARF compilation unit.
	 * <p>
	 * There is some hacky logic here to handle situations where a pointer refers back to
	 * itself via a struct:
	 * <pre>{@literal
	 *   +-> STRUCT1 (creates empty struct)
	 *         +-> Field1: PTRa
	 *               +-> STRUCT1 (empty struct returned from cache)
	 *               ( ptr instance created pointing to empty struct)
	 *         ( struct fields populated )
	 * }</pre>
	 * The struct creation code will stop the recursive loop after the second time
	 * makeDataTypeForPointer() is hit because there will be an empty struct in the cache.
	 *
	 * @param diea
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	private DWARFDataType makeDataTypeForPointer(DIEAggregate diea)
			throws IOException, DWARFExpressionException {

		DWARFDataType refdDT = getDataType(diea.getTypeRef(), voidDDT);
		int byteSize = diea.parseInt(DW_AT_byte_size, diea.getCompilationUnit().getPointerSize());

		// do a second query to see if there was a recursive loop in the call above back
		// to this datatype that resulted in this datatype being created.
		// Use that instance if possible.
		DWARFDataType self = dieOffsetToDataTypeMap.get(diea.getOffset());
		if (self != null) {
			return self;
		}

		if (byteSize == dataTypeManager.getDataOrganization().getPointerSize()) {
			byteSize = -1;// use default pointer size
		}

		DataType resultDataType = (refdDT.dataType instanceof DataTypeImpl)
				? new PointerDataType(refdDT.dataType, byteSize, dataTypeManager)
				: dataTypeManager.resolve(dataTypeManager.getPointer(refdDT.dataType, byteSize),
					DataTypeConflictHandler.DEFAULT_HANDLER);
		return new DWARFDataType(resultDataType, null, diea.getOffset());
	}

	private DWARFDataType makeDataTypeForPtrToMemberType(DIEAggregate diea)
			throws IOException, DWARFExpressionException {

		DWARFNameInfo dni = prog.getName(diea);

		DIEAggregate type = diea.getTypeRef();
		DIEAggregate containingType = diea.getContainingTypeRef();
		if (type == null || containingType == null) {
			Msg.error(this, "No type info for ptr_to_member: " + diea.toString());
			return null;
		}

		int byteSize = diea.parseInt(DW_AT_byte_size, diea.getCompilationUnit().getPointerSize());
		DataType offsetType = dwarfDTM.getOffsetType(byteSize);

		// create a typedef to the offsetType and put containing type and var type info in the typedef name.
		String x = "offset_in_" + containingType.getName() + "_to_" + type.getName();
		DataType dt = new TypedefDataType(dni.getParentCP(), x, offsetType, dataTypeManager);

		if (!dni.isAnon()) {
			dt = new TypedefDataType(dni.getParentCP(), dni.getName(), dt, dataTypeManager);
		}
		return new DWARFDataType(dt, dni, diea.getOffset());
	}

	/**
	 * Creates a {@link TypeDef} datatype.
	 * <p>
	 * If the typedef has the same name as the destination type, create an equiv mapping
	 * pointing to the destination and omit creating a Ghidra typedef.
	 * <p>
	 * If the typedef points (via a pointer) to a function definition type that doesn't
	 * have a name yet, update the function defintion with the name from this typedef
	 * and elide this typedef.
	 * <p>
	 * If the typedef points to a base type (eg int, float, etc), let the base type factory
	 * create the typedef as it can do it better if there are size specifiers in the typedef name
	 * (eg. int64_t).
	 * 
	 * @param diea
	 * @param rec
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	private DWARFDataType makeDataTypeForTypedef(DIEAggregate diea)
			throws IOException, DWARFExpressionException {

		DWARFNameInfo typedefDNI = prog.getName(diea);
		DIEAggregate refdDIEA = diea.getTypeRef();

		if (refdDIEA != null && refdDIEA.getTag() == DW_TAG_base_type) {
			// if this is a typedef to a base type, skip to the base data type which
			// can create a better typedef than we can
			return makeNamedBaseType(typedefDNI, refdDIEA);
		}

		DWARFDataType refdDT = getDataType(refdDIEA, voidDDT);

		// do a second query to see if there was a recursive loop in the call above back
		// to this datatype that resulted in this datatype being created.
		// Use that instance if possible.
		DWARFDataType self = dieOffsetToDataTypeMap.get(diea.getOffset());
		if (self != null) {
			return self;
		}

		boolean typedefWithSameName = DataTypeUtilities.equalsIgnoreConflict(
			typedefDNI.asDataTypePath().getPath(), refdDT.dataType.getPathName());
		if (!typedefWithSameName && refdDT.dataType instanceof Pointer ptrDT &&
			ptrDT.getDataType() instanceof FunctionDefinition pointedToFuncDefDT) {
			// hack to handle funcDefs that produce a ptr_to_funcdef instead of a funcdef type, which messes with name compare
			typedefWithSameName = DataTypeUtilities.equalsIgnoreConflict(
				typedefDNI.asDataTypePath().getPath(), pointedToFuncDefDT.getPathName());
		}

		if (typedefWithSameName) {
			if (importOptions.isElideTypedefsWithSameName()) {
				// this typedef points to something that has the exact same name.  Skip this typedef
				refdDT.offsets.add(diea.getOffset());
				return refdDT;
			}
			// this typedef points to something with the same name.  tweak the typedef's name so
			// there isn't a gratuitous conflict.
			String newName = typedefDNI.getName() + "_typedef";
			typedefDNI = typedefDNI.replaceName(newName, newName);
		}

		TypedefDataType typedefDT = new TypedefDataType(typedefDNI.getParentCP(),
			typedefDNI.getName(), refdDT.dataType, dataTypeManager);
		updateMapping(refdDT.dataType, typedefDT.getDataType());

		return new DWARFDataType(typedefDT, typedefDNI, diea.getOffset());
	}

	/**
	 * Creates a datatype representing the string in the unspecifiedtype dwarf definition.
	 * <p>
	 * Most likely will be a void type.
	 *
	 * @param diea
	 * @return
	 */
	private DWARFDataType makeDataTypeForUnspecifiedType(DIEAggregate diea) {
		DWARFNameInfo dni = prog.getName(diea);
		DataType dt = dwarfDTM.getBaseType(dni.getOriginalName());
		if (dt == null) {
			return voidDDT;
		}
		return new DWARFDataType(dt, dni, diea.getOffset());
	}

	static class DWARFDataType {
		DataType dataType;
		DWARFNameInfo dni;
		DWARFSourceInfo dsi;
		Set<Long> offsets = new HashSet<>();

		DWARFDataType(DataType dataType, DWARFNameInfo dni, long offset) {
			this.dataType = dataType;
			this.dni = dni;
			this.offsets.add(offset);
		}

		DWARFDataType(DataType dataType, DWARFNameInfo dni, Set<Long> offsets) {
			this.dataType = dataType;
			this.dni = dni;
			this.offsets.addAll(offsets);
		}

		@Override
		public String toString() {
			return dataType.getName() + " | " + (dni != null ? dni.toString() : "na") + " | " +
				hexOffsets() + " | zerolen: " + dataType.isZeroLength();
		}

		public String hexOffsets() {
			return offsets.stream()
					.sorted()
					.map(Long::toHexString)
					.collect(
						Collectors.joining(","));
		}

	}
}
