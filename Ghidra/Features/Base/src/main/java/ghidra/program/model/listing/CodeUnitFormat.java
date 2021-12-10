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
package ghidra.program.model.listing;

import java.util.*;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.viewer.field.CommentUtils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowNamespace;
import ghidra.program.model.listing.LabelString.LabelType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.MathUtilities;

public class CodeUnitFormat {

	protected static final String PLUS = "+";
	protected static final String UNDERSCORE = "_";

	//public static String EXTENDED_REFERENCE_DELIMITER_UNICODE = Character.toString((char)0x2192); // symbolic arrow
	public static String EXTENDED_REFERENCE_DELIMITER = "=>";
	public static String EXTENDED_INDIRECT_REFERENCE_DELIMITER = "->";

	/**
	 * Supported memory address shift cases (bits)
	 */
	private static final int[] SHIFT_CASES = new int[] { 1, 2, 8, 16, 32 };

	/**
	 * Supported memory address mask cases (mask value)
	 */
	private static final long[] MASK_CASES = new long[] { 0x0ff, 0x0ffff, 0x0ffffffff };

	/**
	 * Default code unit format
	 */
	public static CodeUnitFormat DEFAULT =
		new CodeUnitFormat(ShowBlockName.NEVER, ShowNamespace.NEVER);

	protected CodeUnitFormatOptions options;

	/**
	 * Default constructor using default format options
	 */
	protected CodeUnitFormat() {
		this(new CodeUnitFormatOptions());
	}

	/**
	 * Format constructor.
	 * 
	 * @param showBlockName whether or not to display block name;
	 *            {SHOW_BLOCKNAME_ALWAYS, SHOW_BLOCKNAME_NEVER,
	 *            SHOW_SEGMENT_NON_LOCAL}
	 * @param showNamespace if true display labels with their name-space path.
	 */
	public CodeUnitFormat(ShowBlockName showBlockName, ShowNamespace showNamespace) {
		this(new CodeUnitFormatOptions(showBlockName, showNamespace));
	}

	/**
	 * Format constructor with more options. Extended reference mark-up is
	 * enabled.
	 * 
	 * @param options format options
	 */
	public CodeUnitFormat(CodeUnitFormatOptions options) {
		this.options = options;
	}

	/**
	 * Returns a formatted string representation of the specified code unit,
	 * including mnemonic and operand(s) only.
	 * 
	 * @param cu code unit
	 * @return formatted code unit representation
	 */
	public String getRepresentationString(CodeUnit cu) {
		return getRepresentationString(cu, false);
	}

	/**
	 * Returns a formatted string representation of the specified code unit
	 * mnemonic and operand(s).
	 * 
	 * @param cu code unit
	 * @param includeEOLcomment if true EOL comment will be appended to code
	 *            unit representation
	 * @return formatted code unit representation
	 */
	public String getRepresentationString(CodeUnit cu, boolean includeEOLcomment) {

		StringBuffer stringBuffer = new StringBuffer(getMnemonicRepresentation(cu));
		if (cu instanceof Instruction) {
			Instruction instr = (Instruction) cu;
			int n = instr.getNumOperands();
			for (int i = 0; i < n; i++) {
				if (i == 0) {
					stringBuffer.append(" ");
				}
				else {
					String separator = instr.getSeparator(i);
					if (separator != null && separator.length() != 0) {
						stringBuffer.append(separator);
					}
				}
				stringBuffer.append(getOperandRepresentationString(cu, i));
			}
		}
		else { // data always has one operand
			stringBuffer.append(" ");
			stringBuffer.append(getOperandRepresentationString(cu, 0));
		}
		if (includeEOLcomment) {
			String eolComment = cu.getComment(CodeUnit.EOL_COMMENT);
			if (eolComment != null) {
				// fixup annotations
				eolComment = CommentUtils.getDisplayString(eolComment, cu.getProgram());
				stringBuffer.append("  // ");
				stringBuffer.append(eolComment);
			}
		}
		return stringBuffer.toString();
	}

	/**
	 * Returns a formatted code unit mnemonic
	 * 
	 * @param cu code unit
	 * @return mnemonic representation
	 */
	public String getMnemonicRepresentation(CodeUnit cu) {
		StringBuffer stringBuffer = new StringBuffer();
		String mnemonic = cu.getMnemonicString();
		if (options.showDataMutability && (cu instanceof Data) && mnemonic != null) {
			Data d = (Data) cu;
			if (d.isConstant()) {
				stringBuffer.append("const ");
			}
			else if (d.isVolatile()) {
				stringBuffer.append("volatile ");
			}
		}
		stringBuffer.append(mnemonic);
		return stringBuffer.toString();
	}

	/**
	 * Returns a formatted string representation of the specified code unit
	 * operand.
	 * 
	 * @param cu code unit
	 * @param opIndex
	 * @return formatted code unit representation
	 */
	public String getOperandRepresentationString(CodeUnit cu, int opIndex) {
		OperandRepresentationList list = getOperandRepresentationList(cu, opIndex);
		if (list == null) {
			return "<UNSUPPORTED>";
		}
		return list.toString();
	}

	/**
	 * Returns a formatted list of operand objects for the specified code unit
	 * operand. In the case of Data opIndex=1, this will be a list containing a
	 * single String object (see getDataValueRepresentation(Data)). In the case
	 * of an Instruction, the list will contain a list of Objects, including any
	 * combination of Character, String, VariableOffset, Register, Address,
	 * Scalar, List, LabelString etc.. All objects returned must support the
	 * toString() method.
	 *
	 * @param cu code unit
	 * @param opIndex operand index
	 * @return list of representation objects or null for an unsupported
	 *         language.
	 */
	public OperandRepresentationList getOperandRepresentationList(CodeUnit cu, int opIndex) {

// TODO: Is locking required ??

// TODO: Concurrent modification handling needed ??

		if (cu instanceof Data) {
			if (opIndex == 0) {
				return getDataValueRepresentation((Data) cu);
			}
			return null;
		}

		Program program = cu.getProgram();
		Instruction instr = (Instruction) cu;
		InstructionPrototype proto = instr.getPrototype();

		if (!program.getLanguage().supportsPcode()) {
			// Formatted mark-up only supported for languages which support PCode
			return null;
		}

		// Get raw representation list and map of registers contained within it
		ArrayList<Object> representationList =
			proto.getOpRepresentationList(opIndex, instr.getInstructionContext());
		if (representationList == null) {
			return new OperandRepresentationList("<BAD-Instruction>");
		}
		HashMap<Register, Integer> regIndexMap = getRegisterIndexMap(representationList);

		Address address = instr.getMinAddress();
		Function func = instr.getProgram().getFunctionManager().getFunctionContaining(address);

		// Get primary reference for specified operand and determine what if any variable it refers to
		Reference primaryRef = cu.getPrimaryReference(opIndex);
		Variable referencedVariable = null;
		if (primaryRef != null && func != null) {
			referencedVariable = program.getReferenceManager().getReferencedVariable(primaryRef);
		}

		// Handle address replacement within operand
		if (performAddressMarkup(instr, opIndex, func, primaryRef, representationList)) {
			primaryRef = null;
			referencedVariable = null;
		}

		// Handle scalar replacement within operand
		// Scalar replacement is the preferred way of representing references in the absence of an address in the raw representation.
		if (performScalarMarkup(instr, opIndex, func, primaryRef, referencedVariable, regIndexMap,
			representationList)) {
			primaryRef = null;
			referencedVariable = null;
		}

		// Handle possible explicit and inferred register references without scalar offset
		// The corresponding register will be replaced by the associated VariableOffset object.
		if (performRegisterMarkup(instr, opIndex, func, primaryRef, referencedVariable, regIndexMap,
			representationList)) {
			primaryRef = null;
			referencedVariable = null;
		}

		// Show non-consumed primary reference by combining with last sub-operand element
		// This corresponds to what we will refer to as Extended Reference Markup"
		if (performExtendedMarkup(instr, primaryRef, referencedVariable, representationList)) {
			primaryRef = null;
			referencedVariable = null;
		}

		return new OperandRepresentationList(representationList, primaryRef != null);
	}

	/**
	 * Perform register markup with explicit and implied register variable
	 * reference.
	 * 
	 * @param inst instruction
	 * @param opIndex
	 * @param func function containing instruction
	 * @param primaryRef primary reference or null
	 * @param referencedVariable option variable referenced by primaryRef
	 * @param regIndexMap register index map
	 * @param representationList
	 * @return true if primaryRef was included in register mark-up
	 */
	private boolean performRegisterMarkup(Instruction instr, int opIndex, Function func,
			Reference primaryRef, Variable referencedVariable,
			HashMap<Register, Integer> regIndexMap, List<Object> representationList) {

		if (func == null || !options.doRegVariableMarkup) {
			return false;
		}

		Program program = instr.getProgram();
		Register referencedRegister = null;
		if (referencedVariable != null && referencedVariable.isRegisterVariable()) {
			referencedRegister = referencedVariable.getRegister();
		}
		else {
			// In the absence of a register reference, check for mnemonic write register reference
			// This is how the decompiler establishes first use assignment of a new variable
// TODO: Not sure if this will circumvent follow-on mark-up for non register variable reference
			ReferenceManager refMgr = program.getReferenceManager();
			for (Reference ref : instr.getReferencesFrom()) {
				if (ref.getOperandIndex() == Reference.MNEMONIC &&
					ref.getReferenceType().isWrite()) {
					referencedVariable = refMgr.getReferencedVariable(ref);
					if (referencedVariable != null && referencedVariable.isRegisterVariable()) {
						primaryRef = ref;
						referencedRegister = referencedVariable.getRegister();
// TODO: Should we allow primaryRef to live-on for additional markup ?
						break;
					}
				}
			}
		}

		// Handle possible explicit and inferred register references without scalar offset
		// The corresponding register will be replaced by the associated VariableOffset object.
		for (Register reg : regIndexMap.keySet()) {
			VariableOffset varOff = null;
			if (registersOverlap(referencedRegister, reg)) {
				varOff = new VariableOffset(primaryRef, referencedVariable);
				primaryRef = null; // reference consumed
				referencedVariable = null;
			}
			else if (options.includeInferredVariableMarkup) {
				boolean isRead = isRead(reg, instr);
				Variable regVar = program.getFunctionManager().getReferencedVariable(
					instr.getMinAddress(), reg.getAddress(), reg.getMinimumByteSize(), isRead);
				if (regVar != null) {
					// TODO: If register appears more than once, how can we distinguish read vs. write occurrence in operands
					if (isRead && isWritten(reg, instr) && !hasRegisterWriteReference(instr, reg) &&
						instr.getRegister(opIndex) != null) {
						// If register both read and written and there are no write references for this instruction
						// see if there is only one reference to choose from - if not we can't determine how to markup
						Variable regWriteVar = program.getFunctionManager().getReferencedVariable(
							instr.getMinAddress(), reg.getAddress(), reg.getMinimumByteSize(),
							false);
						if (regWriteVar != regVar) {
							continue; // TODO: tough case - not which operand is read vs. write!
						}
					}

					// if can't get just a register out of it, assume indirection for the VariableOffset
					long offset = 0;
					varOff = new VariableOffset(regVar, offset, instr.getRegister(opIndex) == null,
						true);
				}
			}
			if (varOff != null) {
				varOff.setReplacedElement(reg);
				representationList.set(regIndexMap.get(reg), varOff);
			}
		}
		return primaryRef == null;
	}

	private boolean registersOverlap(Register reg1, Register reg2) {
		if (reg1 == null || reg2 == null) {
			return false;
		}
		Address reg1MinAddr = reg1.getAddress();
		Address reg2MinAddr = reg2.getAddress();

		Address reg1MaxAddr = reg1MinAddr;
		int size = reg1.getMinimumByteSize();
		if (size > 1) {
			reg1MaxAddr = reg1MinAddr.add(size - 1);
		}
		if (reg2MinAddr.compareTo(reg1MaxAddr) > 0) {
			return false;
		}
		if (reg1MaxAddr.compareTo(reg2MinAddr) < 0) {
			return false;
		}

		Address reg2MaxAddr = reg2MinAddr;
		size = reg1.getMinimumByteSize();
		if (size > 1) {
			reg2MaxAddr = reg2MinAddr.add(size - 1);
		}
		if (reg1MinAddr.compareTo(reg2MaxAddr) > 0) {
			return false;
		}
		if (reg2MaxAddr.compareTo(reg1MinAddr) < 0) {
			return false;
		}

		return true;
	}

	private boolean hasRegisterWriteReference(Instruction instr, Register reg) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isWrite() && ref.getToAddress().equals(reg.getAddress())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * If primaryRef is not already shown in other markup, add to end of operand
	 * representation.
	 * 
	 * @param instr instruction
	 * @param primaryRef primary reference or null
	 * @param referencedVariable optional variable corresponding to primaryRef
	 * @param representationList
	 * @return true if primaryRef was included in extended mark-up
	 */
	private boolean performExtendedMarkup(Instruction instr, Reference primaryRef,
			Variable referencedVariable, List<Object> representationList) {
		// Show non-consumed primary reference by combining with last sub-operand element
		// This corresponds to what we will refer to as Extended Reference Mark-up
		if (!options.alwaysShowPrimaryReference) {
			return false;
		}

		if (primaryRef == null) {
			return false;
		}

		if (representationList.size() == 0) {
			return false;
		}

		Object refRep = getReferenceRepresentation(instr, primaryRef, referencedVariable);
		if (refRep == null) {
			return false;
		}

		OperandRepresentationList compoundList = new OperandRepresentationList();
		int index = representationList.size() - 1;
		compoundList.add(representationList.get(index));
		compoundList.add(EXTENDED_REFERENCE_DELIMITER);
		compoundList.add(refRep);
		representationList.set(index, compoundList);
		return true;
	}

	/**
	 * Attempt to markup any or all addresses contained within the
	 * representationList.
	 * 
	 * @param instr instruction
	 * @param opIndex operand index
	 * @param func function containing instruction
	 * @param primaryRef primary reference
	 * @param referencedVariable optional variable associated with reference
	 * @param regIndexMap register index map
	 * @param representationList
	 * @return true if primaryRef was included in scalar mark-up
	 */
	private boolean performAddressMarkup(Instruction instr, int opIndex, Function func,
			Reference primaryRef, List<Object> representationList) {
		if (primaryRef == null || !primaryRef.isMemoryReference()) {
			return false;
		}
		Address refAddr = primaryRef.getToAddress();

		int size = representationList.size();
		for (int i = 0; i < size; i++) {
			Object obj = representationList.get(i);
			if (!(obj instanceof Address)) {
				continue;
			}
			Address addr = (Address) obj;
			if (refAddr.getPhysicalAddress().equals(addr.getPhysicalAddress())) {
				representationList.set(i, getMemoryReferenceLabel(instr, primaryRef));
				return true;
			}
		}
		return false;
	}

	/**
	 * Attempt to markup any or all Scalars contained within the
	 * representationList.
	 * 
	 * @param inst instruction
	 * @param opIndex operand index
	 * @param function function containing instruction
	 * @param primaryRef primary reference
	 * @param referencedVariable optional variable associated with reference
	 * @param regIndexMap register index map
	 * @param representations
	 * @return true if primaryRef was included in scalar mark-up
	 */
	private boolean performScalarMarkup(Instruction inst, int opIndex, Function function,
			Reference primaryRef, Variable referencedVariable, Map<Register, Integer> regIndexMap,
			List<Object> representations) {

		InstructionScalarInfo info = new InstructionScalarInfo(representations, primaryRef);
		if (info.hasSingleAddressWithNoScalars()) {
			int addressIndex = info.getAddressIndex();
			return markupAddressAsRegister(inst, primaryRef, representations, addressIndex) ||
				markupAddressAsScalar(inst, primaryRef, representations, addressIndex);
		}

		if (info.hasNoScalars()) {
			return false;
		}

		Program program = inst.getProgram();
		List<Equate> equates = null;
		PcodeOp[] pcode = null;
		int size = representations.size();

		for (int i = 0; i < size; i++) {

			Scalar scalar = info.getScalar(i);
			if (scalar == null) {
				continue;
			}

			if (pcode == null) {
				pcode = inst.getPcode(opIndex);
			}

			Register operandRegister = findAssociatedOperandRegister(scalar, regIndexMap, pcode);
			if (operandRegister == null) {
				if (markupScalarWithMemoryReference(inst, scalar, i, primaryRef, representations)) {
					primaryRef = null; // reference consumed - continue handling other scalars
					referencedVariable = null; // we may accidentally consume referenced variable
					continue;
				}
			}
			else if (primaryRef != null && primaryRef.isStackReference()) {
				// Handle explicit stack reference
				// triggered only if scalar is associated with a register in the same operand
				if (markupScalarWithStackReference(scalar, i, primaryRef, referencedVariable,
					representations)) {
					regIndexMap.remove(operandRegister);
					return true;
				}
				return false; // no other mark-up to operand when stack reference applied
			}
			else if (isRegisterAssociatedWithReferencedVariable(referencedVariable,
				operandRegister)) {
				if (markupScalarWithReferencedRegisterVariable(scalar, i, primaryRef,
					referencedVariable, representations)) {
					primaryRef = null; // reference consumed - continue handling other scalars
					referencedVariable = null; // referenced variable consumed
					regIndexMap.remove(operandRegister);
					continue;
				}
			}
			else if (markupScalarWithMemoryReference(inst, scalar, i, primaryRef,
				representations)) {
				primaryRef = null;         // reference consumed - continue handling other scalars
				referencedVariable = null; // signal not to consume referenced variable
				continue;
			}
			else if (markupScalarWithImpliedRegisterVariable(inst, function, scalar, i,
				operandRegister, representations)) {
				regIndexMap.remove(operandRegister);
				continue;
			}

			if (equates == null) {
				equates = program.getEquateTable().getEquates(inst.getMinAddress(), opIndex);
			}
			markupScalarWithEquate(scalar, i, equates, representations);
		}
		return primaryRef == null;
	}

	private boolean markupAddressAsRegister(Instruction instr, Reference primaryRef,
			List<Object> representationList, int addressIndex) {
		if (primaryRef != null) {
			return false;
		}
		// NOTE: although preferrable, access type/size is not considered
		Address addr = (Address) representationList.get(addressIndex);
		Register reg = instr.getProgram().getRegister(addr);
		if (reg != null) {
			representationList.set(addressIndex, reg.getName());
			return true;
		}
		return false;
	}

	private boolean markupAddressAsScalar(Instruction instr, Reference primaryRef,
			List<Object> representationList, int addressIndex) {
		Address addr = (Address) representationList.get(addressIndex);
		AddressSpace space = addr.getAddressSpace();
		long offset = addr.getOffset();
		int unitSize = space.getAddressableUnitSize();
		if (unitSize != 1) {
			if (MathUtilities.unsignedModulo(offset, unitSize) == 0) {
				offset = MathUtilities.unsignedDivide(offset, unitSize);
			}
			else {
				return false;
			}
		}
		else {
			offset = MathUtilities.unsignedDivide(offset, unitSize);
		}

		Scalar scalar = new Scalar(space.getSize(), offset, false);
		if (markupScalarWithMemoryReference(instr, scalar, addressIndex, primaryRef,
			representationList)) {
			return true;
		}
		return primaryRef == null;
	}

	/**
	 * Markup scalar with implied register variable reference if one can be
	 * determined.
	 * 
	 * @param instr instruction
	 * @param func function containing instruction
	 * @param scalarToReplace
	 * @param scalarIndex index of scalarToReplace within representationList
	 * @param associatedRegister register associated with scalarToReplace via an
	 *            INT_ADD operation
	 * @param representationList
	 */
	private boolean markupScalarWithImpliedRegisterVariable(Instruction instr, Function func,
			Scalar scalarToReplace, int scalarIndex, Register associatedRegister,
			List<Object> representationList) {

		if (func == null || !options.doRegVariableMarkup ||
			!options.includeInferredVariableMarkup) {
			return false;
		}

		long scalarValue = scalarToReplace.getValue();
		if (scalarToReplace.isSigned() && scalarValue <= 0) {
			return false;
		}

		Variable regVar =
			instr.getProgram().getFunctionManager().getReferencedVariable(instr.getMinAddress(),
				associatedRegister.getAddress(), associatedRegister.getMinimumByteSize(), true);
		if (regVar == null) {
			return false;
		}

		// TODO: SCR 8400 - prevent this type of markup unless variable is a composite pointer
		// with positive offset within the bounds of the a single composite instance
		DataType dt = removeTypeDefs(regVar.getDataType());
		if (!(dt instanceof Pointer)) {
			return false;
		}

		dt = ((Pointer) dt).getDataType();
		dt = removeTypeDefs(dt);
		if (dt == null || !(dt instanceof Composite) || scalarValue > dt.getLength()) {
			return false;
		}

		VariableOffset variableOffset = new VariableOffset(regVar, scalarValue, true, true);
		variableOffset.setReplacedElement(scalarToReplace,
			options.includeScalarReferenceAdjustment);
		representationList.set(scalarIndex, variableOffset);
		return true;
	}

	private DataType removeTypeDefs(DataType dt) {
		if (dt instanceof TypeDef) {
			return ((TypeDef) dt).getBaseDataType();
		}
		return dt;
	}

	/**
	 * Markup scalar with equate if an appropriate one is contained within the
	 * specified equates list
	 * 
	 * @param scalarToReplace
	 * @param scalarIndex index of scalarToReplace within representationList
	 * @param equates equates for the current code unit operand
	 * @param representationList
	 * @return true if scalar was replaced by equate
	 */
	private boolean markupScalarWithEquate(Scalar scalarToReplace, int scalarIndex,
			List<Equate> equates, List<Object> representationList) {
		if (!equates.isEmpty()) {
			// register association not found - perform equate replacement of matching scalar value
			Equate equate = findEquate(scalarToReplace, equates);
			if (equate != null) {
				representationList.set(scalarIndex, equate);
				return true;
			}
		}
		return false;
	}

	/**
	 *
	 * @param instr
	 * @param scalarToReplace
	 * @param scalarIndex index of scalarToReplace within representationList
	 * @param primaryRef primary reference
	 * @param representationList
	 * @return true if primaryRef was included in scalar mark-up
	 */
	private boolean markupScalarWithMemoryReference(Instruction instr, Scalar scalarToReplace,
			int scalarIndex, Reference primaryRef, List<Object> representationList) {
		if (primaryRef != null && primaryRef.isMemoryReference()) {
			// Apply memory reference to first scalar without a register association
			Object repObj = addScalarAdjustment(getMemoryReferenceLabel(instr, primaryRef),
				primaryRef.getToAddress(), scalarToReplace, representationList.size() == 1);
			if (repObj != null) {
				representationList.set(scalarIndex, repObj);
				return true;
			}
		}
		return false;
	}

	/**
	 * Markup scalar with stack variable/reference
	 * 
	 * @param scalarToReplace
	 * @param scalarIndex index of scalarToReplace within representationList
	 * @param primaryRef stack reference
	 * @param referencedVariable referenced variable or null
	 * @param representationList
	 * @return true if primaryRef was included in scalar mark-up
	 */
	private boolean markupScalarWithStackReference(Scalar scalarToReplace, int scalarIndex,
			Reference primaryRef, Variable referencedVariable, List<Object> representationList) {
		if (options.doStackVariableMarkup) {
			Object varRep =
				getVariableReferenceRepresentation(primaryRef, referencedVariable, scalarToReplace);
			representationList.set(scalarIndex, varRep);
			return true;
		}
		return false;
	}

	/**
	 * Markup scalar with register variable
	 * 
	 * @param scalarToReplace
	 * @param scalarIndex index of scalarToReplace within representationList
	 * @param primaryReference primary reference
	 * @param referencedVariable referenced register variable (required)
	 * @param representationList
	 * @return true if primaryRef was included in scalar mark-up
	 */
	private boolean markupScalarWithReferencedRegisterVariable(Scalar scalarToReplace,
			int scalarIndex, Reference primaryReference, Variable referencedVariable,
			List<Object> representationList) {
		if (options.doRegVariableMarkup) {
			Object variableRepresentation = getVariableReferenceRepresentation(primaryReference,
				referencedVariable, scalarToReplace);
			representationList.set(scalarIndex, variableRepresentation);
			return true;
		}
		return false;
	}

	/**
	 * Determine if the referencedVariable corresponds to the specified
	 * register.
	 * 
	 * @param variable
	 * @param register
	 * @return true if variable is a RegisterVariable corresponding to the
	 *         specified register.
	 */
	private boolean isRegisterAssociatedWithReferencedVariable(Variable variable,
			Register register) {
		if (variable == null || !variable.isRegisterVariable()) {
			return false;
		}
		return (register == variable.getRegister());
	}

	/**
	 * Build register index map based upon a raw operand representation list
	 * where the index corresponds to the index within the list.
	 * 
	 * @param rawRepresentationList
	 * @return register index map
	 */
	private HashMap<Register, Integer> getRegisterIndexMap(List<Object> rawRepresentationList) {
		HashMap<Register, Integer> regIndexMap = new HashMap<>();
		int size = rawRepresentationList.size();
		for (int i = 0; i < size; i++) {
			Object obj = rawRepresentationList.get(i);
			if (obj instanceof Register) {
				// same register multiple times is an odd situation - not handled
				// implementation assumes we will never ever see the same register 3 or more times in same operand
				Register reg = (Register) obj;
				if (regIndexMap.remove(reg) == null) {
					regIndexMap.put(reg, i);
				}
			}
		}
		return regIndexMap;
	}

	/**
	 * Add scalar adjustment markup to the specified opObj. If the specified
	 * addr is a memory address and an adjustment is performed, the "offset "
	 * prefix will also be added to the modified opObj which is returned.
	 * 
	 * @param opObj original sub-operand object
	 * @param addr reference address which corresponds to opObj
	 * @param originalScalar scalar which was replaced by opObj
	 * @param scalarOperand true if operand consists of single scalar only
	 * @return modified opObj with scalar adjustments reflected or null if
	 *         memory address requires excessive adjustment
	 */
	private Object addScalarAdjustment(Object opObj, Address addr, Scalar originalScalar,
			boolean scalarOperand) {

		if (originalScalar == null) {
			return opObj;
		}

		long originalValue = (addr.isStackAddress() &&
			originalScalar.bitLength() == addr.getAddressSpace().getSize())
					? originalScalar.getSignedValue()
					: originalScalar.getUnsignedValue();
		long addrOffset;
		if (addr instanceof SegmentedAddress) {
			addrOffset = ((SegmentedAddress) addr).getSegmentOffset();
		}
		else {
			addrOffset = addr.getAddressableWordOffset();
		}

		if (originalValue == addrOffset || originalValue == addr.getOffset()) {
			return opObj;
		}

		OperandRepresentationList list = new OperandRepresentationList();
		if (addr.isMemoryAddress()) {

			// Include "offset" prefix since addrOffset does not match originalValue
			list.add("offset ");

			// Check for shift cases
			for (int element : SHIFT_CASES) {
				if ((addrOffset >>> element) == originalValue && originalValue != 0x0) {
					list.add(opObj);
					if (options.includeScalarReferenceAdjustment) {
						list.add(" >>");
						list.add(Integer.toString(element));
					}
					return list;
				}
			}

			// Check for mask cases
			for (long element : MASK_CASES) {
				if ((addrOffset & element) == originalValue) {
					list.add(opObj);
					if (options.includeScalarReferenceAdjustment) {
						list.add(" &");
						list.add("0x" + Long.toHexString(element));
					}
					return list;
				}
			}

			// TODO: Check for "reasonable delta value", return null if bad value
			if (!scalarOperand) {
				return null;
			}
		}

		// Handle offset case
		list.add(opObj);
		if (options.includeScalarReferenceAdjustment) {

			long delta = originalValue - addrOffset;
			if (delta < 0) {
				list.add('-');
				delta = -delta;
			}
			else {
				list.add('+');
			}
			list.add(new Scalar(addr.getSize(), delta));
		}
		return list;
	}

	/**
	 * Determine if the specified register is read by the specified instruction.
	 * 
	 * @param register
	 * @param instruction
	 * @return true if register is read
	 */
	private boolean isRead(Register register, Instruction instruction) {
		for (Object obj : instruction.getInputObjects()) {
			if (obj == register) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Determine if the specified register is written by the specified
	 * instruction.
	 * 
	 * @param register
	 * @param instruction
	 * @return true if register is written
	 */
	private boolean isWritten(Register register, Instruction instruction) {
		for (Object obj : instruction.getResultObjects()) {
			if (obj == register) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Search for the register which has the specified address among register
	 * keys contained with in the regIndexMap.
	 * 
	 * @param addr register address
	 * @param regIndexMap register index map
	 * @return register matching register or null if not found.
	 */
	private Register getRegister(Address addr, Map<Register, Integer> regIndexMap) {
		for (Register reg : regIndexMap.keySet()) {
			if (reg.getAddress().equals(addr)) {
				return reg;
			}
		}
		return null;
	}

	/**
	 * Find a register varnode within a map keyed by acceptable register
	 * choices.
	 * 
	 * @param v varnode
	 * @param regIndexMap register index map
	 * @return register which matches varnode, or null.
	 */
	private Register findRegister(Varnode v, Map<Register, Integer> regIndexMap) {
		if (v.isRegister()) {
			Register reg = getRegister(v.getAddress(), regIndexMap);
			if (reg != null) {
				return reg;
			}
		}
		return null;
	}

	/**
	 * Check for value equality between a constant varnode and a scalar value.
	 * 
	 * @param v constant varnode
	 * @param value scalar value
	 * @return true if values are equals
	 */
	private boolean equals(Varnode v, Scalar value) {
		Scalar s = new Scalar(v.getSize() * 8, v.getOffset(), value.isSigned());
		return s.getValue() == value.getValue();
	}

	/**
	 * Find a register which has a direct association with the specified scalar
	 * via an INT_ADD p-code operation. Eligible registers are must be contained
	 * within the regIndexMap.
	 * 
	 * @param scalar
	 * @param regIndexMap registers appearing in operand representation
	 * @param pcode operand p-code
	 * @return associated register, or null if not found
	 */
	private Register findAssociatedOperandRegister(Scalar scalar,
			Map<Register, Integer> regIndexMap, PcodeOp[] pcode) {
		if (regIndexMap.isEmpty() || pcode == null) {
			return null;
		}
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_ADD) {
				Varnode[] inputs = op.getInputs();
				Register reg = null;
				if (inputs[0].isConstant() && equals(inputs[0], scalar)) {
					reg = findRegister(inputs[1], regIndexMap);
				}
				else if (inputs[1].isConstant() && equals(inputs[1], scalar)) {
					reg = findRegister(inputs[0], regIndexMap);
				}
				if (reg != null) {
					return reg;
				}
			}
		}
		return null;
	}

	/**
	 * Search list of equates for scalar value match.
	 * 
	 * @param scalar
	 * @param equates list of equates
	 * @return equate which matches scalar value or null if not found.
	 */
	private Equate findEquate(Scalar scalar, List<Equate> equates) {
		Iterator<Equate> equateItr = equates.iterator();
		while (equateItr.hasNext()) {
			Equate equate = equateItr.next();
			if (equate.getValue() == scalar.getSignedValue() ||
				equate.getValue() == scalar.getValue()) {
				return equate;
			}
		}
		return null;
	}

	/**
	 * Returns a formatted data value for the specified data unit. The return
	 * list will contain a single object which may be an instance of String,
	 * LabelString, Address, Scalar or Equate
	 * 
	 * @param data data unit
	 * @return representation list containing a single object.
	 */
	public OperandRepresentationList getDataValueRepresentation(Data data) {

		Reference ref = data.getPrimaryReference(0);
		OperandRepresentationList representationList = new OperandRepresentationList();

		DataType dataType = data.getDataType();
		int length = data.getLength();

		if ((length != 0 || !dataType.isZeroLength()) && dataType.getLength() > length) {
			representationList.add("Data type \"" + dataType.getDisplayName() +
				"\" is too big for available space. Size = " + dataType.getLength() +
				" bytes, available = " + length + " bytes");
			representationList.setHasError(true);
			representationList.setPrimaryReferenceHidden(ref != null);
			return representationList;
		}

		Object dataValue = data.getValue();

		DataType baseDataType = data.getBaseDataType();
		if (ref != null && !(baseDataType instanceof Composite) &&
			!(baseDataType instanceof Array)) {
			Data parent = data.getParent();
			boolean parentIsUnion = (parent != null && parent.getBaseDataType() instanceof Union);

			if (!parentIsUnion || baseDataType instanceof Pointer || dataValue instanceof Address) {
				Object refRep = getReferenceRepresentation(data, ref, null);
				if (refRep != null) {
					representationList.add(refRep);
					return representationList;
				}
			}
		}

		if (dataValue instanceof Scalar) {
			EquateTable equTable = data.getProgram().getEquateTable();
			Equate equate =
				equTable.getEquate(data.getMinAddress(), 0, ((Scalar) dataValue).getValue());
			if (equate != null) {
				representationList.add(equate);
				representationList.setPrimaryReferenceHidden(ref != null);
				return representationList;
			}
		}

		// Formatting of data deferred to the data type
		if (dataType instanceof Dynamic && ((Dynamic) dataType).canSpecifyLength()) {
			int preferredLength = ((Dynamic) dataType).getLength(data, length);
			if (preferredLength > length) {
				// data overflow
				representationList.setHasError(true);
			}
		}
		representationList.add(dataType.getRepresentation(data, data, length));
		representationList.setPrimaryReferenceHidden(ref != null);
		if (data.isDefined() && dataValue == null) {
			representationList.setHasError(true);
		}
		else if ((dataValue instanceof Address) && ref == null &&
			data.getProgram().getMemory().getBlock((Address) dataValue) == null) {
			representationList.setHasError(true);
		}
		return representationList;
	}

	/**
	 * Returns a formatted data value for the specified data unit.
	 * 
	 * @param data data unit
	 * @return data value string
	 */
	public String getDataValueRepresentationString(Data data) {
		return getDataValueRepresentation(data).toString();
	}

	/**
	 * Build a suitable variable or stack reference representation with optional
	 * scalar replacement.
	 * 
	 * @param ref variable reference
	 * @param var associated variable or null
	 * @param replacedScalar replaced scalar object or null
	 * @return representation object or null if var is null and ref is not a
	 *         stack reference.
	 */
	private Object getVariableReferenceRepresentation(Reference ref, Variable var,
			Scalar replacedScalar) {
		if (var != null) {
			// Relies on reference-type to specify read/write access
			VariableOffset varOffset = new VariableOffset(ref, var);
			varOffset.setReplacedElement(replacedScalar, options.includeScalarReferenceAdjustment);
			return varOffset;
		}
		if (ref.isStackReference()) {
			OperandRepresentationList compoundList = new OperandRepresentationList();
			compoundList.add("Stack");
			compoundList.add('[');
			compoundList.add(new Scalar(32, ((StackReference) ref).getStackOffset(), true));
			compoundList.add(']');
			return addScalarAdjustment(compoundList, ref.getToAddress(), replacedScalar, false);
		}
		return null;
	}

	/**
	 * Returns a marked-up representation of the reference destination.
	 * 
	 * @param fromCodeUnit
	 * @param ref
	 * @return destination as a string or null if a suitable string could not be
	 *         produced.
	 */
	public String getReferenceRepresentationString(CodeUnit fromCodeUnit, Reference ref) {
		// NOTE: The isRead param is false since it really only pertains to register references which should
		// generally only correspond to writes
		Variable refVar = fromCodeUnit.getProgram().getFunctionManager().getReferencedVariable(
			fromCodeUnit.getMinAddress(), ref.getToAddress(), 0, false);
		Object repObj = getReferenceRepresentation(fromCodeUnit, ref, refVar);
		return repObj != null ? repObj.toString() : null;
	}

	/**
	 * Get a representation object corresponding to the specified reference.
	 * Format options are considered when generating label.
	 * 
	 * @param cu
	 * @param ref
	 * @param var variable which corresponds to reference or null
	 * @param showIndirectValue if true, indirect memory references which refer
	 *            to a pointer will get an additional "=value" appended where
	 *            value corresponds to data pointed to by the referenced
	 *            pointer.
	 * @return reference representation object
	 */
	private Object getReferenceRepresentation(CodeUnit cu, Reference ref, Variable var) {
		if (ref == null) {
			return null;
		}

		if (!ref.isExternalReference()) {
			if (var != null || ref.isStackReference() || ref.isRegisterReference()) {
				return getVariableReferenceRepresentation(ref, var, null);
			}
		}

		if (ref.isMemoryReference() || ref.isExternalReference()) {
			return getMemoryReferenceLabel(cu, ref);
		}
		return null;

	}

	/**
	 * Get a LabelString object which corresponds to the specified memory
	 * reference from the specified code unit. Format options are considered
	 * when generating label.
	 * 
	 * @param fromCodeUnit code unit
	 * @param ref memory reference
	 * @return LabelString representation object
	 */
	private Object getMemoryReferenceLabel(CodeUnit fromCodeUnit, Reference ref) {

		Program program = fromCodeUnit.getProgram();
		Address toAddress = ref.getToAddress();

		boolean withBlockName = false;
		MemoryBlock refBlock = null;

		if (toAddress.isMemoryAddress()) {
			Memory mem = program.getMemory();
			refBlock = mem.getBlock(toAddress);
			if (options.showBlockName == ShowBlockName.ALWAYS) {
				withBlockName = true;
			}
			else if (options.showBlockName == ShowBlockName.NON_LOCAL) {
				MemoryBlock block = mem.getBlock(fromCodeUnit.getMinAddress());
				withBlockName = (block != refBlock);
			}
		}

		String result;
		Symbol toSymbol = program.getSymbolTable().getSymbol(ref);
		if (toSymbol != null) {
			result = getSymbolLabelString(program, toSymbol, fromCodeUnit.getMinAddress());
		}
		else {
			result = toAddress.toString();
		}

		result = addBlockName(program, toAddress, result, refBlock, withBlockName);
		LabelType labelType = (toSymbol != null && toSymbol.isExternal()) ? LabelString.EXTERNAL
				: LabelString.CODE_LABEL;
		LabelString label = new LabelString(result, labelType);

		// Apply extended pointer markup if needed
		RefType referenceType = ref.getReferenceType();
		if (options.followReferencedPointers &&
			(referenceType.isIndirect() || ref.getReferenceType() == RefType.READ)) {
			LabelString extLabel = getExtendedPointerReferenceMarkup(program, ref);
			if (extLabel != null) {
				OperandRepresentationList list = new OperandRepresentationList();
				//list.add(label);
				list.add(EXTENDED_INDIRECT_REFERENCE_DELIMITER);
				list.add(extLabel);
				return list;
			}
		}

		return label;
	}

	private LabelString getExtendedPointerReferenceMarkup(Program program, Reference ref) {

		Address toAddress = ref.getToAddress();

		Listing listing = program.getListing();
		if (listing.getDefinedDataAt(toAddress) == null) {
			return null;
		}

		ReferenceManager referenceManager = program.getReferenceManager();
		Reference[] referencesFrom = referenceManager.getReferencesFrom(toAddress);
		if (referencesFrom.length != 1 || referencesFrom[0].getReferenceType() != RefType.DATA) {
			// only follow simple DATA reference type which corresponds to a pointer
			return null;
		}

		Symbol symbol = program.getSymbolTable().getSymbol(referencesFrom[0]);
		if (symbol != null && !symbol.isDynamic()) {
			String result = getSymbolLabelString(program, symbol, ref.getFromAddress());
			return new LabelString(result,
				symbol.isExternal() ? LabelString.EXTERNAL : LabelString.CODE_LABEL);
		}
		return null;
	}

	private String addBlockName(Program program, Address toAddress, String name,
			MemoryBlock refBlock, boolean withBlockName) {

		if (withBlockName && refBlock != null) {
			return refBlock.getName() + Address.SEPARATOR_CHAR + name;
		}

		return name;
	}

	private String addNamespace(Program program, Namespace parentNamespace, String name,
			Address markupAddress) {
		if (parentNamespace == null) {
			return name;
		}

		if (options.showNamespace == ShowNamespace.NEVER) {
			return name;
		}

		if (parentNamespace.getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			return name;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace toNamespace = symbolTable.getNamespace(markupAddress);
		boolean isLocal = parentNamespace.equals(toNamespace);
		if (isLocal && options.showNamespace == ShowNamespace.NON_LOCAL) {
			// do not show namespace for local labels
			return name;
		}
		else if (!isLocal && options.showNamespace == ShowNamespace.LOCAL) {
			// do not show namespace for non-local labels
			return name;
		}

		String namespaceName = null;
		if (isLocal) {
			namespaceName = options.localPrefixOverride;
		}
		if (namespaceName == null) {
			if (!options.showLibraryInNamespace) {
				namespaceName = NamespaceUtils.getNamespacePathWithoutLibrary(parentNamespace);
			}
			else {
				namespaceName = parentNamespace.getName(true);
			}
		}
		if (namespaceName.length() != 0 && !namespaceName.endsWith(Namespace.DELIMITER)) {
			namespaceName += Namespace.DELIMITER;
		}
		return namespaceName + name;
	}

	/**
	 * Generate a string for the given symbol, accounting for offcut situations.
	 */
	private String getSymbolLabelString(Program program, Symbol symbol, Address markupAddress) {
		Address symbolAddress = symbol.getAddress();
		if (symbolAddress.isMemoryAddress()) {
			CodeUnit cu = program.getListing().getCodeUnitContaining(symbolAddress);
			if (isOffcut(symbolAddress, cu)) {
				return getOffcutLabelString(symbolAddress, cu);
			}
			else if (isStringData(cu)) {
				return getLabelStringForStringData((Data) cu, symbol);
			}
		}
		String name = symbol.getName();
		return addNamespace(program, symbol.getParentNamespace(), name, markupAddress);
	}

	private boolean isStringData(CodeUnit cu) {
		if (cu instanceof Data) {
			return ((Data) cu).hasStringValue();
		}
		return false;
	}

	private String getLabelStringForStringData(Data data, Symbol symbol) {
		if (!symbol.isDynamic()) {
			return symbol.getName();
		}
		DataType dataType = data.getBaseDataType();

		//
		// We now have to ask the data type to create an abbreviated form of the text
		//
		String prefix =
			dataType.getDefaultLabelPrefix(data, data, data.getLength(), options.displayOptions);
		if (prefix == null) {
			// data type does not specify default prefix
			return symbol.getName();
		}
		return prefix + UNDERSCORE + SymbolUtilities.getAddressString(symbol.getAddress());
	}

	public String getOffcutLabelString(Address offcutAddress, CodeUnit cu) {
		if (cu instanceof Instruction) {
			return getOffcutLabelStringForInstruction(offcutAddress, (Instruction) cu);
		}
		return getOffcutDataString(offcutAddress, (Data) cu);
	}

	private boolean isOffcut(Address address, CodeUnit cu) {
		if (cu == null) {
			return false;
		}
		return !cu.getMinAddress().equals(address);
	}

	protected String getOffcutDataString(Address offcutAddress, Data data) {
		Program program = data.getProgram();
		Symbol offcutSymbol = program.getSymbolTable().getPrimarySymbol(offcutAddress);
		Address dataAddress = data.getMinAddress();
		int diff = (int) offcutAddress.subtract(dataAddress);
		if (!offcutSymbol.isDynamic()) {
			return getDefaultOffcutString(offcutSymbol, data, diff, false);
		}

		DataType dt = data.getBaseDataType();
		String prefix = getPrefixForStringData(data, dataAddress, diff, dt);
		if (prefix != null) {
			String addressString = SymbolUtilities.getAddressString(dataAddress);
			return addOffcutInformation(prefix, addressString, diff, options.showOffcutInfo);
		}

		return getDefaultOffcutString(offcutSymbol, data, diff, false);
	}

	protected String getOffcutLabelStringForInstruction(Address offcutAddress,
			Instruction instruction) {
		Program program = instruction.getProgram();
		Symbol offsym = program.getSymbolTable().getPrimarySymbol(offcutAddress);
		Address instructionAddress = instruction.getMinAddress();
		long diff = offcutAddress.subtract(instructionAddress);
		if (!offsym.isDynamic()) {
			return getDefaultOffcutString(offsym, instruction, diff, false);
		}

		Symbol containingSymbol = program.getSymbolTable().getPrimarySymbol(instructionAddress);
		if (containingSymbol != null) {
			return containingSymbol.getName() + PLUS + diff;
		}
		return getDefaultOffcutString(offsym, instruction, diff, false);
	}

	protected String addOffcutInformation(String prefix, String addressString, int diff,
			boolean decorate) {
		if (!decorate) {
			return prefix;
		}

		return prefix + UNDERSCORE + addressString + PLUS + diff;
	}

	protected String getPrefixForStringData(Data data, Address dataAddress, int diff, DataType dt) {
		if (data.hasStringValue()) {
			int len = data.getLength();
			return dt.getDefaultOffcutLabelPrefix(data, data, len, options.displayOptions, diff);
		}
		return null;
	}

	protected String getDefaultOffcutString(Symbol symbol, CodeUnit cu, long diff,
			boolean decorate) {
		if (decorate) {
			return symbol.getName() + ' ' + '(' + cu.getMinAddress() + PLUS + diff + ')';
		}
		return symbol.getName();
	}

	/**
	 * Returns ShowBlockName setting
	 */
	public ShowBlockName getShowBlockName() {
		return options.showBlockName;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * A simple class to find the scalars and addresses in the operand
	 * representation list and to keep track of whether to process a scalar with
	 * a zero value.
	 */
	private class InstructionScalarInfo {

		boolean processZeroScalar = false;
		int scalarCount = 0;
		int addressCount = 0;
		int lastAddressIndex = -1;

		private List<Object> representationList;

		InstructionScalarInfo(List<Object> representationList, Reference primaryRef) {

			this.representationList = representationList;
			boolean hasZeroScalar = false;
			int size = representationList.size();
			for (int i = 0; i < size; i++) {
				Object obj = representationList.get(i);
				if (obj instanceof Scalar) {
					if (((Scalar) obj).getUnsignedValue() == 0) {
						hasZeroScalar = true;
					}
					else {
						++scalarCount;
						addressCount = 0; // scalar markup takes precedence
					}

				}
				else if (obj instanceof Address) {
					if (scalarCount == 0) {
						++addressCount;
						lastAddressIndex = i;
					}
				}
			}

			if (hasZeroScalar && scalarCount == 0 && addressCount == 0 && primaryRef == null) {
				// only process zero scalar when no other scalar or address found and no reference
				++scalarCount;
				processZeroScalar = true;
			}
		}

		Scalar getScalar(int index) {
			Object obj = representationList.get(index);
			if (!(obj instanceof Scalar)) {
				return null;
			}

			Scalar scalar = (Scalar) obj;
			if (scalar.getUnsignedValue() == 0) {
				return processZeroScalar ? scalar : null;
			}
			return scalar;
		}

		boolean hasSingleAddressWithNoScalars() {
			return scalarCount == 0 && addressCount == 1;
		}

		int getAddressIndex() {
			return lastAddressIndex;
		}

		boolean hasNoScalars() {
			return scalarCount == 0;
		}
	}
}
