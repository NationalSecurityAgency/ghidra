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
package ghidra.app.plugin.core.codebrowser;

import static ghidra.GhidraOptions.*;

import java.awt.Color;
import java.awt.Component;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.field.FieldElement;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.Highlight;
import ghidra.GhidraOptions;
import ghidra.GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES;
import ghidra.app.plugin.processors.generic.PcodeFieldFactory;
import ghidra.app.services.ButtonPressedListener;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.datastruct.Stack;

public class ListingHighlightProvider
		implements ButtonPressedListener, OptionsChangeListener, HighlightProvider {

	private static final String DISPLAY_HIGHLIGHT_NAME =
		CURSOR_HIGHLIGHT_GROUP + DELIMITER + "Enabled";

	private static final String SCOPED_WRITE_HIGHLIGHT_COLOR =
		CURSOR_HIGHLIGHT_GROUP + DELIMITER + "Scoped Write Highlight Color";

	private static final String SCOPED_READ_HIGHLIGHT_COLOR =
		CURSOR_HIGHLIGHT_GROUP + DELIMITER + "Scoped Read Highlight Color";

	private static final String SCOPE_REGISTER_OPERAND =
		CURSOR_HIGHLIGHT_GROUP + DELIMITER + "Scope Register Operand";

	private static char[] UNDERSCORE_AND_PERIOD_OK = new char[] { '.', '_' };
	private static char[] UNDERSCORE_OK = new char[] { '_' };

	private final static Highlight[] NO_HIGHLIGHTS = new Highlight[0];

	private Pattern currentHighlightPattern;
	private String currentHighlightString;
	private boolean displayHighlight;

	private Color textMatchingHighlightColor;
	private Color scopeWriteHighlightColor;
	private Color scopeReadHighlightColor;

	private int highlightButtonOption;
	private boolean scopeRegisterHighlight;

	private AddressSet scope; // places that are within scope
	private Long variableMatchFirstUseOffset; // first use offset which corresponds to variable of interest
	private AddressSet writeScope; // places that are written

	private BrowserCodeUnitFormat format; // code unit format which tracks code browser

	private final Component repaintComponent;
	private final PluginTool tool;

	public ListingHighlightProvider(PluginTool tool, Component repaintComponent) {
		this.tool = tool;
		this.repaintComponent = repaintComponent;

		format = new BrowserCodeUnitFormat(tool);

		setupHighlightOptions();
	}

	protected void dispose() {
		currentHighlightString = null;
		currentHighlightPattern = null;
	}

	@Override
	public Highlight[] getHighlights(String text, Object obj,
			Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset) {
		if (scopeRegisterHighlight && scope != null) {
			if (fieldFactoryClass == VariableNameFieldFactory.class ||
				fieldFactoryClass == VariableLocFieldFactory.class) {
				if (obj instanceof Variable) {
					Variable var = (Variable) obj;
					if (variableMatchFirstUseOffset != null &&
						var.getFirstUseOffset() == variableMatchFirstUseOffset) {
						return getTextHighlights(null, text);
					}
				}
			}
			if (fieldFactoryClass == OperandFieldFactory.class ||
				fieldFactoryClass == PcodeFieldFactory.class) {
				if (obj instanceof Instruction) {
					Instruction instr = (Instruction) obj;
					return getTextHighlights(instr.getMinAddress(), text);
				}
			}
			return NO_HIGHLIGHTS;
		}
		return getTextHighlights(null, text);
	}

	private Highlight[] getTextHighlights(Address addr, String text) {
		String highlightString = currentHighlightString;
		if (text == null || highlightString == null) {
			return NO_HIGHLIGHTS;
		}

		Color color = textMatchingHighlightColor;
		if (addr != null && scope != null && scope.contains(addr)) {
			color = scopeReadHighlightColor;
		}

		if (addr != null && writeScope != null && writeScope.contains(addr)) {
			color = scopeWriteHighlightColor;
		}

		Pattern highlightPattern = currentHighlightPattern;
		Matcher matcher = highlightPattern.matcher(text);
		List<Highlight> highlightList = new ArrayList<Highlight>();
		while (matcher.find()) {
			int start = matcher.start();
			int end = matcher.end() - 1;
			if (scope == null || isWholeWord(text, start, end)) {
				highlightList.add(new Highlight(start, end, color));
			}
		}
		if (highlightList.size() < 1) {
			return NO_HIGHLIGHTS;
		}
		return highlightList.toArray(new Highlight[highlightList.size()]);
	}

	private boolean isWholeWord(String text, int start, int end) {
		if (start > 0) {
			char c = text.charAt(start - 1);
			if (Character.isLetterOrDigit(c)) {
				return false;
			}
		}
		if (end < text.length() - 1) {
			char c = text.charAt(end + 1);
			if (Character.isLetterOrDigit(c)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void buttonPressed(ProgramLocation location, FieldLocation fieldLocation,
			ListingField field, MouseEvent event) {
		if (event == null) {
			return;
		}

		if (!displayHighlight) {
			return;
		}

		if (event.getButton() == highlightButtonOption) {
			// get the string at the mouse pointer location
			setHighlightString(location.getProgram(), getStringToHighlight(field,
				fieldLocation.getRow(), fieldLocation.getCol(), location));
		}
	}

	// a null value clears the highlight as well as passing the same highlight value
	private void setHighlightString(Program program, String highlightString) {
		if (highlightString == null || highlightString.equals(currentHighlightString)) {
			// a repeated highlight signals to turn off the current highlight
			clearHighlight();
			return;
		}

		currentHighlightString = highlightString;

		repaintComponent.repaint();
	}

	private void clearHighlight() {
		currentHighlightString = null;
		currentHighlightPattern = null;
		repaintComponent.repaint();
	}

	private Pattern createRegisterPattern(Register register, String... highlightStrings) {

		List<String> registerNames = gatherRegisterNames(new ArrayList<String>(), register);

		for (String s : highlightStrings) {
			if (s != null) {
				registerNames.add(s);
			}
		}

		// Prioritize exact register matches by ensuring that the longest register name gets
		// matched first
		Collections.sort(registerNames, (a, b) -> {
			return Integer.valueOf(b.length()).compareTo(Integer.valueOf(a.length()));
		});

		StringBuilder buffy = new StringBuilder();
		for (String name : registerNames) {
			buffy.append("\\Q").append(name).append("\\E|");
		}

		if (buffy.length() != 0) {
			// remove trailing pipe
			buffy.deleteCharAt(buffy.length() - 1);
		}

		// search for literal case sensitive register/variable names
		return Pattern.compile(buffy.toString());
	}

	private List<String> gatherRegisterNames(List<String> names, Register register) {

		// get the parents
		Register parent = register.getParentRegister();
		while (parent != null) {
			names.add(parent.getName());
			parent = parent.getParentRegister();
		}

		// now the register and its children
		accumulateSubRegisters(names, register);

		return names;
	}

	private void accumulateSubRegisters(List<String> names, Register register) {
		names.add(register.getName());

		List<Register> childRegisters = register.getChildRegisters();
		for (Register childRegister : childRegisters) {
			accumulateSubRegisters(names, childRegister);
		}
	}

	private String getStringToHighlight(ListingField tf, int row, int col, ProgramLocation loc) {
		if (!(tf instanceof ListingTextField)) {
			return null;
		}
		scope = null;
		variableMatchFirstUseOffset = null;

		ListingTextField ltf = (ListingTextField) tf;
		Object proxyObj = tf.getProxy().getObject();
		FieldElement fieldElement = ltf.getFieldElement(row, col);

		String text = null; // selected text and primary search string
		String altText = null; // alternate search text (e.g., variable name which corresponds to selected register)
		Register register = null; // register which corresponds to selection
		Variable var = null; // variable which corresponds to selection
		Varnode refVarnode = null; // selected stack/memory varnode
		Instruction instr = null; // instr from where register scoping should begin

		if ((loc instanceof OperandFieldLocation) && (proxyObj instanceof Instruction)) {

			instr = (Instruction) proxyObj;
			OperandFieldLocation opLoc = (OperandFieldLocation) loc;

			OperandRepresentationList opRepList =
				format.getOperandRepresentationList(instr, opLoc.getOperandIndex());
			Object object = opRepList.get(opLoc.getSubOperandIndex());

			int elementCol = ltf.screenToDataLocation(row, col).col() -
				fieldElement.getDataLocationForCharacterIndex(0).col();

			if (object instanceof OperandRepresentationList) {
				// extended markup contained within OperandRepresentationList
				// some elements may be strings where we need to access a
				// specific "word" - thus the need to adjust col when
				// object is modified

				text = fieldElement.getText();

				// identify object corresponding fieldElement
				for (Object listObj : (OperandRepresentationList) object) {
					String str = listObj.toString();
					if (text.equals(str)) {
						object = listObj;
						break;
					}
				}
			}
			// Check object which may have been selected from within a
			// compound OperandRepresentationList (e.g., EAX=>localVAR
			if (object instanceof Register) {
				register = (Register) object;
				text = register.getName();
			}
			else if (object instanceof VariableOffset) {
				VariableOffset varOff = (VariableOffset) object;
				var = varOff.getVariable();
				text = var.getName();
				boolean selectSubElement = (elementCol > text.length()); // e.g., field2 selected in "stackVar.field2"
// FIXME: fix pointer case, e.g., stackVar->field2 (check offset value which may be misleading for pointer case)
				if (selectSubElement) {
					String offsetStr =
						StringUtilities.findWord(object.toString(), elementCol, UNDERSCORE_OK);
					if (offsetStr != null && offsetStr.length() > 0) {
						text = offsetStr;
					}
				}
				if (!selectSubElement && varOff.isIndirect()) {
					// keep variable (i.e., pointer tracking)
				}
				else if ((var.isStackVariable() || var.isMemoryVariable()) &&
					(selectSubElement || varOff.getOffset() == 0)) {
					// Varnodes only work with references which generally only exist
					// for stack and memory
					Varnode[] varnodes = getVarnodes(varOff);
					if (varnodes == null || varnodes.length != 1) {
						var = null; // limit to simple text highlight
					}
					else {
						refVarnode = varnodes[0];
					}
				}
				else if (selectSubElement) {
					var = null; // limit to simple text highlight
				}
			}
			else if (object instanceof Character) {
				text = buildStringFromChars(text, opLoc, opRepList);
			}
			else if (object instanceof LabelString) {
				text = object.toString();
			}
			else {
				text = StringUtilities.findWord(object.toString(), elementCol,
					UNDERSCORE_AND_PERIOD_OK);
			}

		}
		else if ((loc instanceof PcodeFieldLocation) && (proxyObj instanceof Instruction)) {
			// at present just handle register selection from within pcode display
			// for non-register to be interpreted as a register
			instr = (Instruction) proxyObj;
			int pos = ltf.screenLocationToTextOffset(row, col);
			text = StringUtilities.findWord(ltf.getText(), pos, UNDERSCORE_OK);
			register = instr.getProgram().getRegister(text);

			if (register != null) {
				// attempt to locate associated variable
				Reference ref = new MemReferenceImpl(instr.getAddress(), register.getAddress(),
					RefType.DATA, SourceType.ANALYSIS, 0, true);
				var = instr.getProgram().getReferenceManager().getReferencedVariable(ref);
				if (var != null) {
					altText = var.getName(); // also match on associated variable name
				}
			}
		}
		else if (loc instanceof LabelFieldLocation) {
			text = ((LabelFieldLocation) loc).getName();
		}
		else if ((proxyObj instanceof Variable)) {
			var = (Variable) proxyObj;
			if (loc instanceof VariableNameFieldLocation) {
				text = var.getName();
			}
			else if (loc instanceof VariableLocFieldLocation) {
				// at present just handle register selection from with variable storage string
				int pos = ltf.screenLocationToTextOffset(row, col);
				text = StringUtilities.findWord(ltf.getText(), pos, UNDERSCORE_OK);
				register = var.getProgram().getRegister(text);
				altText = var.getName();
			}
		}

		Address firstUseAddr = null;
		if (var != null) {
			if (register == null) {
				register = var.getRegister();
			}
			variableMatchFirstUseOffset = (long) var.getFirstUseOffset();
			firstUseAddr = var.getFunction().getEntryPoint().add(variableMatchFirstUseOffset);
			if (instr == null) {
				instr = var.getProgram().getListing().getInstructionAt(firstUseAddr);
			}
		}

		if (register != null) {
			currentHighlightPattern = createRegisterPattern(register, text, altText);
			if (scopeRegisterHighlight && instr != null) {

				if (SystemUtilities.isEqual(currentHighlightString, text)) {
					// skip setting the scope; middle-mousing the same text signals to disable the highlight
					return text;
				}

				// if is a register, build up scope of register
				scope = new AddressSet();
				writeScope = new AddressSet();
				scope.addRange(instr.getMinAddress(), instr.getMaxAddress());
				followScope(register, instr, firstUseAddr);
			}
			return text;
		}
		else if (var != null && instr != null &&
			(var.isStackVariable() || var.isMemoryVariable())) {
			// NOTE: assumed scoped highlight (no option - although we could
			// reuse reg option)

			if (SystemUtilities.isEqual(currentHighlightString, text)) {
				// skip setting the scope; middle-mousing the same text signals
				// to disable the highlight
				return text;
			}

			// build up scope using references into refVarnode
			scope = new AddressSet();
			writeScope = new AddressSet();
			scope.addRange(instr.getMinAddress(), instr.getMaxAddress());
			followScope(var, refVarnode, instr);
		}

		if (text == null) {
			text = ltf.getText();
			int pos = ltf.screenLocationToTextOffset(row, col);
			text = StringUtilities.findWord(text, pos, UNDERSCORE_AND_PERIOD_OK);
		}

		if (StringUtils.isBlank(text)) {
			text = null;
		}
		else {
			text = text.trim();
			currentHighlightPattern = Pattern.compile(text, Pattern.LITERAL);
		}

		return text;
	}

	private String buildStringFromChars(String text, OperandFieldLocation opLoc,
			OperandRepresentationList opRepList) {
		StringBuilder buf = new StringBuilder();
		for (int i = opLoc.getSubOperandIndex(); i < opRepList.size(); i++) {
			Object obj = opRepList.get(i);
			if (!(obj instanceof Character)) {
				break;
			}
			buf.append(obj);
		}
		text = buf.toString().trim();
		if (text.length() == 0) {
			text = null;
		}
		return text;
	}

	private Set<Register> getRegisterSet(Register reg) {
		Set<Register> regSet = new HashSet<Register>();
		regSet.add(reg);
		Register r = reg.getParentRegister();
		while (r != null) {
			regSet.add(r);
			r = r.getParentRegister();
		}
		addChildren(reg, regSet);
		return regSet;
	}

	private void addChildren(Register reg, Set<Register> regSet) {
		for (Register r : reg.getChildRegisters()) {
			regSet.add(r);
			addChildren(r, regSet);
		}
	}

	private void initFunctionSubSet(AddressSet subSet, Function func, Instruction instr,
			Address firstUseAddr) {

		subSet.add(func.getBody());

		// if instr is before function entry - only include range with instr but
		// not beyond function entry
		if (instr.getAddress().compareTo(func.getEntryPoint()) < 0) {
			AddressRange rangeContaining = subSet.getRangeContaining(instr.getAddress());
			Address addr = func.getEntryPoint().previous();
			if (rangeContaining != null && addr != null) {
				rangeContaining =
					rangeContaining.intersectRange(rangeContaining.getMinAddress(), addr);
				subSet = subSet.intersectRange(rangeContaining.getMinAddress(),
					rangeContaining.getMaxAddress());
			}
		}

		// if firstUseAddr specified, only include addresses at or below firstUseAddr
		if (firstUseAddr != null) {
			subSet = subSet.intersectRange(firstUseAddr, subSet.getMaxAddress());
		}

	}

	private void initUndefinedFunctionSubSet(AddressSet subSet, Instruction instr) {
		// if there is no function, then just follow some flow backwards
		Program prog = instr.getProgram();
		int count = 0;
		Instruction followInstr = instr;
		while (count < 100 && followInstr != null &&
			!subSet.contains(followInstr.getMinAddress())) {
			count++;
			subSet.addRange(followInstr.getMinAddress(), followInstr.getMaxAddress());
			Address fallFrom = followInstr.getFallFrom();
			if (fallFrom == null) {
				ReferenceIterator iter = followInstr.getReferenceIteratorTo();
				if (!iter.hasNext()) {
					break;
				}
				Reference ref = iter.next();
				// don't follow calls!
				if (ref.getReferenceType().isCall()) {
					break;
				}
				fallFrom = ref.getFromAddress();
			}
			followInstr = prog.getListing().getInstructionContaining(fallFrom);
		}
	}

	private interface WriteChecker {
		boolean hasWrite(Instruction instr);
	}

	private void setScopeBeforeInstruction(Instruction instr, AddressSet subSet,
			WriteChecker writeChecker) {
		// follow flow backwards until writeChecker indicates hasWrite
		// and set writeScope, all other instructions upto that point will be
		// added to read scope
		Program prog = instr.getProgram();
		Stack<Address> backStack = new Stack<Address>();
		pushInstructionBackFlows(instr, backStack);
		while (!backStack.isEmpty()) {
			Address addr = backStack.pop();
			if (addr == null) {
				continue;
			}
			if (!subSet.contains(addr)) {
				continue;
			}
			subSet.deleteRange(addr, addr);
			Instruction fInstr = prog.getListing().getInstructionAt(addr);
			if (fInstr == null) {
				continue;
			}
			scope.addRange(fInstr.getMinAddress(), fInstr.getMaxAddress());
			if (writeChecker.hasWrite(fInstr)) {
				writeScope.addRange(fInstr.getMinAddress(), fInstr.getMaxAddress());
				continue;
			}
			pushInstructionBackFlows(fInstr, backStack);
		}
	}

	private void setScopeAfterInstruction(Instruction instr, AddressSet subSet,
			WriteChecker writeChecker) {
		// follow flow downwards until register is changed
		// add in each line that has register anywhere
		Program prog = instr.getProgram();
		Stack<Address> stack = new Stack<Address>();
		pushInstructionFlows(instr, stack);
		while (!stack.isEmpty()) {
			Address addr = stack.pop();
			if (addr == null) {
				continue;
			}
			if (!subSet.contains(addr)) {
				continue;
			}
			subSet.deleteRange(addr, addr);
			Instruction fInstr = prog.getListing().getInstructionAt(addr);
			if (fInstr == null) {
				continue;
			}
			if (writeChecker.hasWrite(fInstr)) {
				continue;
			}
			scope.addRange(fInstr.getMinAddress(), fInstr.getMaxAddress());
			pushInstructionFlows(fInstr, stack);
		}
	}

	private void followScope(Variable var, Varnode refVarnode, Instruction instr) {

		if (refVarnode == null) {
			return;
		}

		AddressSet subSet = new AddressSet();
		Program prog = instr.getProgram();
		Function func = var.getFunction();

		// Collect variable write references to refVarnode
		Reference[] references = prog.getReferenceManager().getReferencesTo(var);
		AddressSet writeRefSet = new AddressSet();
		for (Reference ref : references) {
			if (ref.getReferenceType().isWrite() && !ref.getReferenceType().isRead() &&
				refVarnode.contains(ref.getToAddress())) {
				writeRefSet.add(ref.getFromAddress());
			}
		}

		initFunctionSubSet(subSet, func, instr, null);

		WriteChecker writeChecker = fInstr -> writeRefSet.contains(fInstr.getAddress());

		// if this instruction writes refVarnode, don't need to track back
		// since this is the start of the scope
		if (writeRefSet.contains(instr.getAddress())) {
			writeScope.addRange(instr.getMinAddress(), instr.getMaxAddress());
		}
		else {
			setScopeBeforeInstruction(instr, subSet, writeChecker);
		}

		setScopeAfterInstruction(instr, subSet, writeChecker);
	}

	private void followScope(Register register, Instruction instr, Address firstUseAddr) {
		// get address set that represents subroutine

		Set<Register> regSet = getRegisterSet(register);

		AddressSet subSet = new AddressSet();
		Program prog = instr.getProgram();
		Function func = prog.getFunctionManager().getFunctionContaining(instr.getMinAddress());
		if (func != null) {
			initFunctionSubSet(subSet, func, instr, firstUseAddr);
		}
		else {
			initUndefinedFunctionSubSet(subSet, instr);
		}
		if (subSet.isEmpty()) {
			return;
		}

		WriteChecker writeChecker = fInstr -> isWriteOnly(regSet, fInstr);

		// if this instruction loads the register, don't need to track back
		// since this is the start of the scope
		if (isWriteOnly(regSet, instr)) {
			writeScope.addRange(instr.getMinAddress(), instr.getMaxAddress());
		}
		else {
			setScopeBeforeInstruction(instr, subSet, writeChecker);
		}

		setScopeAfterInstruction(instr, subSet, writeChecker);
	}

	private void pushInstructionBackFlows(Instruction instr, Stack<Address> backStack) {
		ReferenceIterator refIter = instr.getReferenceIteratorTo();
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (ref.getReferenceType().isFlow()) {
				Address addr = ref.getFromAddress();
				if (addr.compareTo(instr.getMinAddress()) < 0) {
					// Only consider back flow to prevent loop issues
					backStack.push(addr);
				}
			}
		}
		Address fallFrom = instr.getFallFrom();
		if (fallFrom != null) {
			backStack.push(fallFrom);
		}
	}

	private void pushInstructionFlows(Instruction instruction, Stack<Address> stack) {
		Instruction instr = instruction;
		Address[] flowAddrs = instr.getFlows();
		for (Address addr : flowAddrs) {
			// if (addr.compareTo(instruction.getMaxAddress()) > 0)
			{
				// Only consider forward flow to prevent loop issues
				stack.push(addr);
			}
		}
		stack.push(instr.getFallThrough());

		int depth = instr.getDelaySlotDepth();
		for (int i = 0; i < depth; i++) {
			try {
				Address nextAddr = instr.getMaxAddress().addNoWrap(1);
				instr = instr.getProgram().getListing().getInstructionAt(nextAddr);
				stack.push(nextAddr);
			}
			catch (AddressOverflowException e) {
				break;
			}
			if (instr == null) {
				break;
			}
			pushInstructionFlows(instr, stack);
		}
	}

	private boolean isWriteOnly(Set<Register> regSet, Instruction instr) {
		boolean isWriteOnly = false;

		// look to see if is written
		Varnode vn = null;
		Object[] resObjs = instr.getResultObjects();
		for (Object element : resObjs) {
			if (element instanceof Register) {
				Register resReg = (Register) element;
				if (regSet.contains(resReg)) {
					isWriteOnly = true;
					vn = new Varnode(resReg.getAddress(), resReg.getMinimumByteSize());
					break;
				}
			}
		}

		if (!isWriteOnly) {
			return false;
		}

		// Simplified check for real write to register
		PcodeOp[] pcode = instr.getPcode();
		for (int i = pcode.length - 1; i >= 0; i--) {
			if (vn.equals(pcode[i].getOutput())) {
				int opcode = pcode[i].getOpcode();
				if (opcode == PcodeOp.INT_XOR) {
					if (pcode[i].getInput(0).equals(pcode[i].getInput(1))) {
						return true;
					}
				}
				else if (opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT) {
					return true;
				}
				else if (opcode == PcodeOp.LOAD) {
					return true;
				}
				else if (opcode == PcodeOp.COPY) {
					vn = pcode[i].getInput(0);
				}
			}
		}

		// look to see if is read
		Object[] inObjs = instr.getInputObjects();
		for (Object element : inObjs) {
			if (element instanceof Register) {
				Register inReg = (Register) element;
				if (regSet.contains(inReg)) {
					isWriteOnly = false;
					break;
				}
			}
		}

		return isWriteOnly;
	}

	/**
	 * Attempt to identify variable varnodes which correspond to this variable
	 * reference.
	 * 
	 * @return array of varnodes or null if failed to identify
	 */
	private Varnode[] getVarnodes(VariableOffset varOffset) {

		if (varOffset.isIndirect()) {
			return null;
		}

		boolean dataAccess = varOffset.isDataAccess();

		Variable variable = varOffset.getVariable();
		long offset = varOffset.getOffset();

		long absOffset = offset < 0 ? -offset : offset;
		if (absOffset > Integer.MAX_VALUE) {
			return null;
		}

		VariableStorage variableStorage = variable.getVariableStorage();
		if (variableStorage.size() <= 0) {
			return null; // invalid storage
		}

		DataType dt = variable.getDataType();

		int varnodeOffset = 0;
		int varnodeSize = 0;

		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}

		int intOff = (int) absOffset;
		while (intOff > 0 || (dataAccess && intOff == 0)) {
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}
			if (dt instanceof Structure) {
				DataTypeComponent cdt = ((Structure) dt).getComponentAt(intOff);
				if (cdt == null) {
					break;
				}
				varnodeOffset += cdt.getOffset();
				intOff -= cdt.getOffset();
				dt = cdt.getDataType();
			}
			else {
				// Primitives, Unions and Arrays are treated as single varnode
				break;
			}
		}

		varnodeSize = dt.getLength();
		if (varnodeSize <= 0 || intOff > varnodeSize) {
			return null;
		}

		varnodeSize -= intOff;
		varnodeOffset += intOff;

		List<Varnode> varnodes = new ArrayList<Varnode>();
		for (Varnode v : variableStorage.getVarnodes()) {
			if (varnodeOffset >= v.getSize()) {
				varnodeOffset -= v.getSize();
				continue;
			}
			int size = Math.min(v.getSize(), varnodeSize);
			varnodeSize -= size;
			varnodes.add(new Varnode(v.getAddress().add(varnodeOffset), size));
			if (varnodeSize == 0) {
				break;
			}
			varnodeOffset = 0;
		}

		return varnodes.toArray(new Varnode[varnodes.size()]);
	}

	private void setupHighlightOptions() {
		ToolOptions opt = tool.getOptions(CATEGORY_BROWSER_FIELDS);
		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "Cursor_Text_Highlight");

		opt.registerOption(HIGHLIGHT_COLOR_NAME, Color.YELLOW, hl,
			"The color to use to highlight text.");
		opt.registerOption(SCOPED_WRITE_HIGHLIGHT_COLOR, new Color(204, 204, 0), hl,
			"The color to use for showing a register being written.");
		opt.registerOption(SCOPED_READ_HIGHLIGHT_COLOR, new Color(0, 255, 0), hl,
			"The color to use for showing a register being read.");

		opt.registerOption(SCOPE_REGISTER_OPERAND, true, hl,
			"Enables register scoping for text highlighting." +
				"When a register is highlighted, only its scoped use is highlighted");
		opt.registerOption(DISPLAY_HIGHLIGHT_NAME, true, hl, "Enables cursor text highlighting.");
		opt.registerOption(CURSOR_HIGHLIGHT_BUTTON_NAME,
			GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES.MIDDLE, hl,
			"Selects which mouse button should be used to active cursor text highlighting");

		opt.addOptionsChangeListener(this);

		/////////////////////////////////////////////////////

		displayHighlight = opt.getBoolean(DISPLAY_HIGHLIGHT_NAME, true);
		if (!displayHighlight) {
			setHighlightString(null, null);
		}

		textMatchingHighlightColor = opt.getColor(HIGHLIGHT_COLOR_NAME, Color.YELLOW);

		scopeWriteHighlightColor =
			opt.getColor(SCOPED_WRITE_HIGHLIGHT_COLOR, new Color(204, 204, 0));
		scopeReadHighlightColor = opt.getColor(SCOPED_READ_HIGHLIGHT_COLOR, new Color(0, 255, 0));

		/////////////////////////////////////////////////////

		CURSOR_MOUSE_BUTTON_NAMES mouseButton =
			opt.getEnum(CURSOR_HIGHLIGHT_BUTTON_NAME, CURSOR_MOUSE_BUTTON_NAMES.MIDDLE);

		highlightButtonOption = mouseButton.getMouseEventID();

		//////////////////////////////////////////////////////

		scopeRegisterHighlight = opt.getBoolean(SCOPE_REGISTER_OPERAND, true);

		//////////////////////////////////////////////////////

		opt.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(DISPLAY_HIGHLIGHT_NAME)) {
			displayHighlight = ((Boolean) newValue).booleanValue();
			if (!displayHighlight) {
				clearHighlight();
			}
		}
		else if (optionName.equals(HIGHLIGHT_COLOR_NAME)) {
			textMatchingHighlightColor = (Color) newValue;
		}
		else if (optionName.equals(SCOPED_WRITE_HIGHLIGHT_COLOR)) {
			scopeWriteHighlightColor = (Color) newValue;
		}
		else if (optionName.equals(SCOPED_READ_HIGHLIGHT_COLOR)) {
			scopeReadHighlightColor = (Color) newValue;
		}
		else if (optionName.equals(CURSOR_HIGHLIGHT_BUTTON_NAME)) {
			CURSOR_MOUSE_BUTTON_NAMES mouseButton = (CURSOR_MOUSE_BUTTON_NAMES) newValue;
			highlightButtonOption = mouseButton.getMouseEventID();
		}
		else if (optionName.equals(SCOPE_REGISTER_OPERAND)) {
			scopeRegisterHighlight = ((Boolean) newValue).booleanValue();
		}
	}
}
