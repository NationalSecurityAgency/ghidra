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
package ghidra.app.plugin.core.decompile.actions;

import java.awt.Font;
import java.awt.FontMetrics;
import java.util.List;

import javax.swing.JMenuItem;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Abstract pop-up menu convert action for the decompiler. If triggered, it lays down
 * a new EquateReference that forces the selected constant to be displayed using
 * the desired integer format.
 */
public abstract class ConvertConstantAction extends AbstractDecompilerAction {

	/**
	 * Max instructions to search through, when looking for a scalar match in the listing
	 * that corresponds with the selected constant in the decompiler window.
	 */
	private final static int MAX_INSTRUCTION_WINDOW = 20;
	protected DecompilePlugin plugin;
	private FontMetrics metrics = null;
	private int convertType;				// The EquateSymbol conversion type performed by the action

	/**
	 * A helper class describing a (matching) scalar operand
	 */
	private static class ScalarMatch {
		Address refAddr;		// Address of instruction
		Scalar scalar;
		int opIndex;

		public ScalarMatch(Address addr, Scalar value, int index) {
			refAddr = addr;
			scalar = value;
			opIndex = index;
		}
	}

	public ConvertConstantAction(DecompilePlugin plugin, String name, int convertType) {
		super(name);
		this.plugin = plugin;
		this.convertType = convertType;
	}

	private int stringWidth(String s) {
		if (metrics == null) {
			JMenuItem item = new JMenuItem();
			Font font = item.getFont();
			metrics = plugin.getTool().getActiveWindow().getFontMetrics(font);
		}
		int w = metrics.stringWidth(s);
		if (w == 0) {
			// use default computation if metrics report 0
			return 10 * s.length();
		}
		return w;
	}

	protected String getStandardLengthString(String baseString) {
		int baseWidth = stringWidth(baseString);
		int spaceWidth = stringWidth(" ");
		int paddingSize = (140 - baseWidth) / spaceWidth;
		if (paddingSize <= 0) {
			return baseString;
		}
		StringBuilder buf = new StringBuilder(baseString);
		for (int i = 0; i < paddingSize; i++) {
			buf.append(" ");
		}
		return buf.toString();
	}

	/**
	 * Find a scalar in the instruction matching one of the given values.
	 * Return an object describing the match or null if there is no match.
	 * @param instr is the instruction
	 * @param values is an array of the given values
	 * @return the Scalar and
	 */
	private ScalarMatch findScalarInInstruction(Instruction instr, long values[]) {
		int numOperands = instr.getNumOperands();
		ScalarMatch scalarMatch = null;
		for (int i = 0; i < numOperands; i++) {
			for (Object obj : instr.getOpObjects(i)) {
				if (obj instanceof Scalar) {
					Scalar scalar = (Scalar) obj;
					for (long value : values) {
						if (scalar.getUnsignedValue() != value) {
							continue;
						}
						if (scalarMatch != null) {
							scalarMatch.opIndex = -1;	// non-unique scalar operand value - can't identify operand
							return scalarMatch;
						}
						scalarMatch = new ScalarMatch(instr.getAddress(), scalar, i);
					}
				}
			}
		}
		return scalarMatch;
	}

	/**
	 * Find a scalar (instruction operand) that matches the given constant Varnode.
	 * We walk backward from the starting address inspecting operands until a match is found.
	 * The search is terminated if either a match is found, the beginning of the basic block
	 * is reached, or if 20 instructions are traversed.  The scalar can be a "near" match, meaning
	 * off by 1 or the negated value.
	 * @param program is the Program
	 * @param startAddress is the starting address to search backward from
	 * @param constVn is the given constant Varnode
	 * @param monitor is the TaskMonitor
	 * @return a description of the scalar match, or null if there is no match
	 * @throws CancelledException if the user cancels
	 */
	private ScalarMatch findScalarMatch(Program program, Address startAddress, Varnode constVn,
			TaskMonitor monitor) throws CancelledException {
		long value = constVn.getOffset();
		long mask = -1;
		if (constVn.getSize() < 8) {
			mask = mask >>> (8 - constVn.getSize()) * 8;
		}
		long values[] = new long[4];
		values[0] = value;
		values[1] = (value - 1) & mask;
		values[2] = (value + 1) & mask;
		values[3] = (-value) & mask;
		int count = 0;
		ScalarMatch scalarMatch = null;
		Instruction curInst = program.getListing().getInstructionAt(startAddress);
		if (curInst == null) {
			return null;
		}
		SimpleBlockModel model = new SimpleBlockModel(program);
		CodeBlock basicBlock = model.getFirstCodeBlockContaining(startAddress, monitor);
		if (basicBlock == null) {
			return null;
		}
		while (count < MAX_INSTRUCTION_WINDOW) {
			count += 1;
			ScalarMatch newMatch = findScalarInInstruction(curInst, values);
			if (newMatch != null) {
				if (scalarMatch != null) {
					return null;		// Matches at more than one address
				}
				if (newMatch.opIndex < 0) {
					return null;		// Matches at more than one operand
				}
				scalarMatch = newMatch;
			}
			curInst = curInst.getPrevious();
			if (curInst == null) {
				break;
			}
			if (!basicBlock.contains(curInst.getAddress())) {
				break;
			}
		}
		return scalarMatch;
	}

	/**
	 * Given the context, set up the task object that will execute the conversion.
	 * If setupFinal toggle is false, only enough of the task is set up to complete
	 * the isEnabled test for the action.  Otherwise the whole task is set up, ready for runTask().
	 * If the context is not suitable for a conversion, null is returned.
	 * @param context is the given context for the action
	 * @param setupFinal is true if a full task setup is needed
	 * @return the task object or null
	 */
	protected ConvertConstantTask establishTask(DecompilerActionContext context,
			boolean setupFinal) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (!(tokenAtCursor instanceof ClangVariableToken)) {
			return null;
		}
		Varnode convertVn = tokenAtCursor.getVarnode();
		if (convertVn == null || !convertVn.isConstant()) {
			return null;
		}
		HighSymbol symbol = convertVn.getHigh().getSymbol();
		EquateSymbol convertSymbol = null;
		if (symbol != null) {
			if (symbol instanceof EquateSymbol) {
				convertSymbol = (EquateSymbol) symbol;
				int type = convertSymbol.getConvert();
				if (type == convertType || type == EquateSymbol.FORMAT_DEFAULT) {
					return null;
				}
			}
			else {
				return null;		// Something already attached to constant
			}
		}
		DataType convertDataType = convertVn.getHigh().getDataType();
		boolean convertIsSigned = false;
		if (convertDataType instanceof AbstractIntegerDataType) {
			if (convertDataType instanceof BooleanDataType) {
				return null;
			}
			convertIsSigned = ((AbstractIntegerDataType) convertDataType).isSigned();
		}
		else if (convertDataType instanceof Enum) {
			return null;
		}
		if (!setupFinal) {
			return new ConvertConstantTask(convertVn, convertIsSigned);
		}

		ConvertConstantTask task = null;

		String equateName = getEquateName(convertVn.getOffset(), convertVn.getSize(),
			convertIsSigned, context.getProgram());
		if (equateName == null) {		// A null is a user cancel
			return null;
		}
		Program program = context.getProgram();
		Address convertAddr;
		long convertHash;
		if (convertSymbol != null) {
			convertAddr = convertSymbol.getPCAddress();
			convertHash = 0;
			int convertIndex = -1;
			boolean foundEquate = false;
			EquateTable equateTable = program.getEquateTable();
			List<Equate> equates = equateTable.getEquates(convertAddr);
			for (Equate equate : equates) {
				if (equate.getValue() != convertVn.getOffset()) {
					continue;
				}
				for (EquateReference equateRef : equate.getReferences(convertAddr)) {
					convertHash = equateRef.getDynamicHashValue();
					convertIndex = equateRef.getOpIndex();
					foundEquate = true;
					break;
				}
				break;
			}
			if (!foundEquate) {
				Msg.error(this, "Symbol does not have matching entry in equate table");
				return null;
			}
			task = new ConvertConstantTask(context, equateName, convertAddr, convertVn, convertHash,
				convertIndex);
		}
		else {
			PcodeOp op = convertVn.getLoneDescend();
			convertAddr = op.getSeqnum().getTarget();

			DynamicHash dynamicHash = new DynamicHash(convertVn, 0);
			convertHash = dynamicHash.getHash();
			task = new ConvertConstantTask(context, equateName, convertAddr, convertVn, convertHash,
				-1);
			try {
				ScalarMatch scalarMatch = findScalarMatch(context.getProgram(), convertAddr,
					convertVn, TaskMonitor.DUMMY);
				if (scalarMatch != null) {
					long value = scalarMatch.scalar.getUnsignedValue();
					int size = scalarMatch.scalar.bitLength() / 8;
					if (size == 0) {
						size = 1;
					}
					String altName = getEquateName(value, size, convertIsSigned, null);
					if (altName == null) {
						altName = equateName;
					}
					// Don't create a named equate if the varnode and the instruction operand differ
					// as the name was selected specifically for the varnode
					if (convertType != EquateSymbol.FORMAT_DEFAULT ||
						value == convertVn.getOffset()) {
						task.setAlternate(altName, scalarMatch.refAddr, scalarMatch.opIndex, value);
					}
				}
			}
			catch (CancelledException e) {
				// scalar match is not added to task
			}
		}
		return task;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		ConvertConstantTask task = establishTask(context, false);
		if (task == null) {
			return false;
		}
		String convDisplay = getMenuDisplay(task.getValue(), task.getSize(), task.isSigned());
		if (convDisplay.equals(context.getTokenAtCursor().getText())) {
			return false;
		}
		String menuString = getStandardLengthString(getMenuPrefix()) + convDisplay;
		getPopupMenuData().setMenuItemName(menuString);
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		ConvertConstantTask task = establishTask(context, true);
		if (task == null) {
			return;
		}
		task.runTask();
	}

	/**
	 * The menu option for this kind of action is intended to look like:
	 *    {@literal Hexadecimal: 0x2408}
	 *  This method establishes the first part of this string, up to the colon.
	 * @return the menu prefix
	 */
	public abstract String getMenuPrefix();

	/**
	 * The menu option for this kind of action is intended to look like:
	 *    {@literal Hexadecimal: 0x2408}
	 * This method constructs the final part of this string, after the colon by
	 * formatting the actual value that is to be converted.
	 * @param value is the actual value
	 * @param size is the number of bytes used for the constant Varnode
	 * @param isSigned is true if the constant represents a signed data-type
	 * @return the formatted String
	 */
	public abstract String getMenuDisplay(long value, int size, boolean isSigned);

	/**
	 * Construct the name of the Equate, either absolutely for a conversion or
	 * by preventing the user with a dialog to select a name.
	 * @param value is the value being converted
	 * @param size is the number of bytes used for the constant Varnode
	 * @param isSigned is true if the constant represents a signed data-type
	 * @param program is the current Program
	 * @return the equate name
	 */
	public abstract String getEquateName(long value, int size, boolean isSigned, Program program);
}
