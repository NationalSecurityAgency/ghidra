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

import java.util.List;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.actions.ConvertConstantAction.NearMatchValues;
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
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import utility.function.Callback;

/**
 * Create an equate in the table for the specific Address and hash value.
 * The equate is not assumed to be attached to a particular instruction operand and
 * uses the dynamic hash value to identify the particular constant (within p-code) to label.
 *
 * If altAddress is non-null and the other alt* fields are filled in, the task attempts
 * to set the equation on the altAddress first to get the representation of the p-code
 * constant at convertAddress to change.  After the decompilation finishes, the representation
 * is checked, and if it did not change, the alt* equate is removed and an equate is created
 * directly for the convertAddress;
 */
public class ConvertConstantEquateTask implements Callback {
	/**
	 * Max instructions to search through, when looking for a scalar match in the listing
	 * that corresponds with the selected constant in the decompiler window.
	 */
	private final static int MAX_INSTRUCTION_WINDOW = 20;

	private static final int MAX_SCALAR_SIZE = 8;
	private DecompilerActionContext context;
	private Program program;
	private Scalar convertValue;		// Constant being converted
	private Address convertAddress;		// The primary address of the Equate
	private String convertName;			// The primary name to use in the Equate table
	private long convertHash;			// A dynamic hash locating the constant Varnode in data-flow
	private int convertIndex;			// The scalar index associated with the primary Equate (or -1)

	private Address altAddress = null;	// Alternate location of constant
	private int altIndex;				// Index of alternate scalar
	private String altName = null;		// Alternate equate name
	private long altValue;				// Alternate value 

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

	/**
	 * Construct a primary Equate task
	 * @param context is the action context for the task
	 * @param name is the primary Equate name
	 * @param addr is the primary address of the Equate
	 * @param scalar is the equate constant
	 * @param hash is the dynamic hash
	 * @param index is the operand index if the Equate is known to label an instruction operand
	 */
	public ConvertConstantEquateTask(DecompilerActionContext context, String name, Address addr,
			Scalar scalar, long hash, int index) {
		this.context = context;
		program = context.getProgram();
		convertValue = scalar;
		convertName = name;
		convertAddress = addr;
		convertHash = hash;
		convertIndex = index;
	}

	/**
	 * If the mouse context is on a constant that it suitable for a conversion using this task,
	 * return a description of the constant.  Otherwise return null.
	 * @param context is the mouse context
	 * @param convertType is the type of conversion being selected (FORMAT_DEC FORMAT_HEX etc.)
	 * @return the constant description or null
	 */
	static protected Scalar getConvertibleConstant(DecompilerActionContext context,
			int convertType) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (!(tokenAtCursor instanceof ClangVariableToken)) {
			return null;
		}
		Varnode convertVn = tokenAtCursor.getVarnode();
		if (convertVn == null || !convertVn.isConstant() || convertVn.getSize() > MAX_SCALAR_SIZE) {
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
		return new Scalar(convertVn.getSize() * 8, convertVn.getOffset(), convertIsSigned);
	}

	/**
	 * Establish an alternate Equate to try before falling back on the primary Equate
	 * @param name is the alternate name of the Equate
	 * @param addr is the alternate address
	 * @param index is the operand index
	 * @param value is the alternate constant value to equate
	 */
	public void setAlternate(String name, Address addr, int index, long value) {
		altName = name;
		altAddress = addr;
		altValue = value;
		altIndex = index;
	}

	/**
	 * Remove any pre-existing equate reference with the same address and hash as the
	 * primate equate.
	 */
	private void removePrimaryReference() {
		EquateTable equateTable = program.getEquateTable();
		List<Equate> equates = equateTable.getEquates(convertAddress);
		for (Equate equate : equates) {
			List<EquateReference> references = equate.getReferences(convertAddress);
			for (EquateReference ref : references) {
				if (ref.getDynamicHashValue() == convertHash) {
					if (equate.getReferenceCount() <= 1) {
						equateTable.removeEquate(equate.getName());
					}
					else {
						equate.removeReference(convertHash, convertAddress);
					}
					return;
				}
			}
		}
	}

	/**
	 * Remove and pre-existing equate reference with the same address and hash as the
	 * alternate equate.
	 */
	private void removeAlternateReference() {
		EquateTable equateTable = program.getEquateTable();
		List<Equate> equates = equateTable.getEquates(altAddress);
		for (Equate equate : equates) {
			List<EquateReference> references = equate.getReferences(altAddress);
			for (EquateReference ref : references) {
				if (ref.getOpIndex() == altIndex) {
					if (equate.getReferenceCount() <= 1) {
						equateTable.removeEquate(equate.getName());
					}
					else {
						equate.removeReference(altAddress, altIndex);
					}
					return;
				}
			}
		}
	}

	/**
	 * Add equate based on the alternate constant information: altAddress, altName, altIndex
	 * @throws DuplicateNameException if there is already an equate with same name but different value
	 * @throws InvalidInputException if the equate name is illegal
	 */
	private void addPrimaryEquate() throws DuplicateNameException, InvalidInputException {
		EquateTable equateTable = program.getEquateTable();
		Equate equate = equateTable.getEquate(convertName);

		if (equate != null && equate.getValue() != convertValue.getValue()) {
			String msg = "Equate named " + convertName + " already exists with value of " +
				equate.getValue() + ".";
			throw new DuplicateNameException(msg);
		}

		if (equate == null) {
			equate = equateTable.createEquate(convertName, convertValue.getValue());
		}

		// Add reference to existing equate
		if (convertHash != 0) {
			equate.addReference(convertHash, convertAddress);
		}
		else {
			equate.addReference(convertAddress, convertIndex);
		}
	}

	/**
	 * Add equate based on the direct constant information: convertAddress, convertName, convertHash
	 * @throws DuplicateNameException if there is already an equate with same name but different value
	 * @throws InvalidInputException if the equate name is illegal
	 */
	private void addAlternateEquate() throws InvalidInputException, DuplicateNameException {
		EquateTable equateTable = program.getEquateTable();
		Equate equate = equateTable.getEquate(altName);

		if (equate != null && equate.getValue() != altValue) {
			String msg = "Equate named " + altName + " already exists with value of " +
				equate.getValue() + ".";
			throw new DuplicateNameException(msg);
		}

		if (equate == null) {
			equate = equateTable.createEquate(altName, altValue);
		}

		equate.addReference(altAddress, altIndex);
	}

	/**
	 * Create a reference to primary equate, removing any previous reference.
	 * If an alternate equate is given, remove any existing reference to it as well.
	 */
	private void applyPrimaryEquate() {

		int transaction = program.startTransaction("Convert constant");
		boolean commit = false;
		try {
			if (altAddress != null) {
				removeAlternateReference();
			}
			removePrimaryReference();
			addPrimaryEquate();
			commit = true;
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Convert Failed", e.getMessage());
		}
		catch (InvalidInputException e) {
			Msg.showError(this, null, "Convert Failed", e.getMessage());
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	/**
	 * Create a reference to the alternate equate.
	 */
	private void applyAlternateEquate() {
		int transaction = program.startTransaction("Convert constant");
		boolean commit = false;
		try {
			addAlternateEquate();
			commit = true;
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Convert Failed", e.getMessage());
		}
		catch (InvalidInputException e) {
			Msg.showError(this, null, "Convert Failed", e.getMessage());
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	/**
	 * Look for the EquateSymbol pointing to the altAddress, attached to the constant
	 * @return true if we find the EquateSymbol, false otherwise
	 */
	private boolean isAlternatePlaced() {
		HighFunction highFunction = context.getHighFunction();	// Get the updated HighFunction
		if (highFunction == null) {
			return false;
		}
		// Varnode itself should be unchanged
		Varnode vn = DynamicHash.findVarnode(highFunction, convertAddress, convertHash);
		if (vn == null) {
			return false;
		}
		HighSymbol symbol = vn.getHigh().getSymbol();	// But now it should have an equate on it
		if (!(symbol instanceof EquateSymbol)) {
			return false;
		}
		EquateSymbol eqSymbol = (EquateSymbol) symbol;
		if (!eqSymbol.getPCAddress().equals(altAddress)) {
			return false;
		}
		return true;
	}

	/**
	 * Callback executed after the alternative equate is placed and the DecompilerProvider has updated its window.
	 * We check to see if the equate reached the desired constant in the decompiler.
	 * If not, we remove the alternate equate and place a direct equate
	 */
	@Override
	public void call() {
		if (isAlternatePlaced()) {
			return;
		}
		applyPrimaryEquate();
	}

	/**
	 * Run the convert task.  If the task is given an alternate equate, this is placed, otherwise
	 * the primary equate is placed.  If an alternate is placed, a thread is scheduled to check if
	 * the alternate equate reached the constant Varnode.  If not the alternate equate reference is
	 * removed, and the task falls back and places the primary equate.
	 */
	public void runTask() {
		if (altAddress != null) {
			applyAlternateEquate();
			try {
				Thread.sleep(50);		// Let the decompiler get going
			}
			catch (InterruptedException e) {
				return;
			}
			context.getComponentProvider().doWhenNotBusy(this);
		}
		else {
			applyPrimaryEquate();
		}
	}

	/**
	 * Find a scalar in the instruction matching one of the given values.
	 * Return an object describing the match or null if there is no match.
	 * @param instr is the instruction
	 * @param values is set of given nearby values
	 * @return the Scalar and
	 */
	private static ScalarMatch findScalarInInstruction(Instruction instr, NearMatchValues values) {
		int numOperands = instr.getNumOperands();
		ScalarMatch scalarMatch = null;
		for (int i = 0; i < numOperands; i++) {
			for (Object obj : instr.getOpObjects(i)) {
				if (obj instanceof Scalar) {
					Scalar scalar = (Scalar) obj;
					if (values.isMatch(scalar.getValue())) {
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
	 * Find a scalar (instruction operand) that matches the given constant.
	 * We walk backward from the starting address inspecting operands until a match is found.
	 * The search is terminated if either a match is found, the beginning of the basic block
	 * is reached, or if 20 instructions are traversed.  The scalar can be a "near" match, meaning
	 * off by 1 or the negated value.
	 * @param program is the Program
	 * @param startAddress is the starting address to search backward from
	 * @param scalar is the constant value to search for
	 * @return a description of the scalar match, or null if there is no match
	 */
	private static ScalarMatch findScalarMatch(Program program, Address startAddress,
			Scalar scalar) {
		NearMatchValues values = new NearMatchValues(scalar);
		int count = 0;
		ScalarMatch scalarMatch = null;
		Instruction curInst = program.getListing().getInstructionAt(startAddress);
		if (curInst == null) {
			return null;
		}

		SimpleBlockModel model = new SimpleBlockModel(program);
		CodeBlock basicBlock = null;
		try {
			basicBlock = model.getFirstCodeBlockContaining(startAddress, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen; dummy monitor
		}
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

	private static ConvertConstantEquateTask convertExistingSymbol(DecompilerActionContext context,
			ConvertConstantAction action, EquateSymbol convertSymbol, Scalar scalar) {
		Address convertAddr = convertSymbol.getPCAddress();
		long convertHash = 0;
		int convertIndex = -1;
		boolean foundEquate = false;
		Program program = context.getProgram();
		EquateTable equateTable = program.getEquateTable();
		List<Equate> equates = equateTable.getEquates(convertAddr);
		NearMatchValues values = new NearMatchValues(scalar);
		for (Equate equate : equates) {
			if (!values.isMatch(equate.getValue()))
				continue;
			for (EquateReference equateRef : equate.getReferences(convertAddr)) {
				convertHash = equateRef.getDynamicHashValue();
				convertIndex = equateRef.getOpIndex();
				foundEquate = true;
				break;
			}
			break;
		}
		if (!foundEquate) {
			Msg.error(action, "Symbol does not have matching entry in equate table");
			return null;
		}

		String equateName =
			action.getEquateName(scalar, context.getProgram());
		if (equateName == null) {		// A null is a user cancel
			return null;
		}
		return new ConvertConstantEquateTask(context, equateName, convertAddr, scalar, convertHash,
			convertIndex);
	}

	/**
	 * Given the context, set up the task object that will execute the conversion.
	 * If the context is not suitable for a conversion, null is returned.
	 * @param context is the given context for the action
	 * @param action is the parent action for this task
	 * @return the task object or null
	 */
	protected static ConvertConstantEquateTask establishTask(DecompilerActionContext context,
			ConvertConstantAction action) {

		Scalar scalar =
			ConvertConstantEquateTask.getConvertibleConstant(context, action.convertType);
		Varnode varnode = context.getTokenAtCursor().getVarnode();
		HighSymbol symbol = varnode.getHigh().getSymbol();
		if (symbol instanceof EquateSymbol) {
			return convertExistingSymbol(context, action, (EquateSymbol) symbol, scalar);
		}

		PcodeOp op = varnode.getLoneDescend();
		Address convertAddr = op.getSeqnum().getTarget();
		DynamicHash dynamicHash = new DynamicHash(varnode, 0);
		long convertHash = dynamicHash.getHash();
		Program program = context.getProgram();
		ScalarMatch scalarMatch = findScalarMatch(program, convertAddr, scalar);
		if (scalarMatch == null) {
			String equateName =
				action.getEquateName(scalar, program);
			if (equateName == null) {
				return null; // A null is a user cancel
			}
			return new ConvertConstantEquateTask(context, equateName, convertAddr, scalar,
				convertHash, -1);
		}

		Scalar matchScalar = scalarMatch.scalar;
		if (matchScalar.bitLength() < 8 || matchScalar.isSigned() != scalar.isSigned()) {
			int size = matchScalar.bitLength();
			if (size < 8)
				size = 8;
			matchScalar = new Scalar(size, matchScalar.getUnsignedValue(), scalar.isSigned());
		}
		String equateName = action.getEquateName(matchScalar, program);
		if (equateName == null) {
			return null; // user cancelled
		}

		ConvertConstantEquateTask task =
			new ConvertConstantEquateTask(context, equateName, convertAddr, scalar, convertHash,
				-1);

		// Don't create a named equate if the varnode and the instruction operand differ
		// as the name was selected specifically for the varnode
		if (action.convertType != EquateSymbol.FORMAT_DEFAULT ||
			matchScalar.getValue() == scalar.getValue()) {
			task.setAlternate(equateName, scalarMatch.refAddr, scalarMatch.opIndex,
				matchScalar.getValue());
		}
		return task;
	}
}
