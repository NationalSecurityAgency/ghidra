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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.regex.Matcher;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractLabelMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Applier for {@link AbstractLabelMsSymbol} symbols.
 */
public class LabelSymbolApplier extends MsSymbolApplier {

	private AbstractLabelMsSymbol symbol;
	private Function function = null;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 */
	public LabelSymbolApplier(DefaultPdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof AbstractLabelMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		symbol = (AbstractLabelMsSymbol) abstractSymbol;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		// A naked label seems to imply an assembly procedure, unlike that applyTo(MsSymbolApplier),
		// which is used for applying to something else (basically a block sequence of symbols,
		// as is seen with GlobalProcedure symbols), in which case it is typically an instruction
		// label within those functions.

		// This is getting the label, regardless of PdbApplicatorOptions flag which is only used
		// for instruction labels within functions.
		String label = symbol.getName();

		Address symbolAddress = applicator.getAddress(symbol);
		if (applicator.isInvalidAddress(symbolAddress, label)) {
			return;
		}

		// Create function or label, depending on what is indicated.  Note that the indicator is
		//  sufficient, but not necessary for a function; thus, we might not create a function
		//  where one exists.  However, other analyses, such as EntryPointAnalysis might pick
		//  this up.
		if (hasFunctionIndication()) {
			// The applyFunction call hierarchy here, was copied and modified from
			// FunctionSymbolApplier.  We need to re-look at this and create common as possibly
			// in applicator or utility or else where. Note that our applyFunction here does not
			// apply a function definition, as we have no data type associated with the label.
			applyFunction(symbolAddress, label, applicator.getCancelOnlyWrappingMonitor());
		}
		else {
			applicator.createSymbol(symbolAddress, label, true);
		}
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		String label = getLabel();
		if (label == null) {
			return;
		}

		Address symbolAddress = applicator.getAddress(symbol);
		if (applicator.isInvalidAddress(symbolAddress, label)) {
			return;
		}

		if (applyToApplier instanceof FunctionSymbolApplier functionSymbolApplier) {
			Function f = functionSymbolApplier.getFunction();
			if (f != null && !f.getName().equals(label)) {
				label = NamespaceUtils.getNamespaceQualifiedName(f, label, true);
			}
		}

		// No longer doing this, but instead letting namespace come from GPROC sequence... that way,
		// labels will pertain to functions even if landing inside other function address range.
		// Keeping code here (commented out), replaced by above code, until we get other issues
		// figured out.
//		FunctionManager functionManager = applicator.getProgram().getFunctionManager();
//		// TODO: What do we do with labels such as this?... "__catch$?test_eh1@@YAHXZ$7"
//		if (!label.contains(Namespace.DELIMITER)) {
//			Function f = functionManager.getFunctionContaining(symbolAddress);
//			if (f != null && !f.getName().equals(label)) {
//				label = NamespaceUtils.getNamespaceQualifiedName(f, label, true);
//			}
//		}

		// TODO: Before we turn on label applications.... we probably need to change order on
		// how function symbols are applied.  Perhaps we need to apply all GPROC symbols before
		// we apply their internals (frames, local vars, labels, blocks) because some labels (here)
		// are getting applied and becoming primary (because some have addresses that are located
		// outside of the the address range of their GPROC, and will prevent another GPROC at the
		// same address as the label from becoming primary (e.g., $LN7 of cn3 at a750).
		applicator.createSymbol(symbolAddress, label, false);
	}

	/**
	 * Returns true if seems like a function.  Not necessary, but (seems) sufficient, to indicate a
	 *  function
	 * @return true if function indicated
	 */
	private boolean hasFunctionIndication() {
		return symbol.getFlags().hasFunctionIndication();
	}

	/**
	 * Returns true if there is a specific indication that the function is non-returning.
	 * @return true if positive indication is given
	 */
	private boolean isNonReturning() {
		return symbol.getFlags().doesNotReturn();
	}

	// Note that this flag is available in any ProcedureFlags, but we have not yet seen it set,
	// and we are not sure how it might conflict with a calling convention found in the attributes
	// of a ProcedureMsType (not sure that we see a ProcedureMsType for a "Label" but might for
	// a ProcedureStart symbol, which is where we might have the conflict).  For now, we are
	// creating this method here because we are not anticipating a conflict with a specified
	// calling convention.
	/**
	 * Returns true if there is a specific indication that the function has a custom calling
	 * convention.
	 * @return true if positive indication is given
	 */
	private boolean hasCustomCallingConvention() {
		return symbol.getFlags().hasCustomCallingConvention();
	}

	private boolean applyFunction(Address address, String name, TaskMonitor monitor) {
		applicator.createSymbol(address, name, true);
		function = createFunction(address, monitor);
		if (function == null) {
			return false;
		}

		if (!function.isThunk() &&
			function.getSignatureSource().isLowerPriorityThan(SourceType.IMPORTED)) {
			// For LabelSymbolApplier, we don't have a function definition to set, unlike for
			// FunctionSymbolApplier and ManagedProcedureApplier!

			// We can check for non-returning and custom calling convention, however
			function.setNoReturn(isNonReturning());
			// We have seen no examples of custom calling convention flag being set.
			if (hasCustomCallingConvention()) {
				try {
					function.setCallingConvention("unknown");
				}
				catch (InvalidInputException e) {
					Msg.warn(this,
						"PDB: Could not set \"unknown\" calling convention for label: " + name);
				}
			}
		}
		return true;
	}

	private Function createFunction(Address address, TaskMonitor monitor) {

		// Check for existing function.
		Function myFunction = applicator.getProgram().getListing().getFunctionAt(address);
		if (myFunction != null) {
			return myFunction;
		}

		// Disassemble
		Instruction instr = applicator.getProgram().getListing().getInstructionAt(address);
		if (instr == null) {
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);
			cmd.applyTo(applicator.getProgram(), monitor);
		}

		myFunction = createFunctionCommand(address, monitor);

		return myFunction;
	}

	private Function createFunctionCommand(Address address, TaskMonitor monitor) {
		CreateFunctionCmd funCmd = new CreateFunctionCmd(address);
		if (!funCmd.applyTo(applicator.getProgram(), monitor)) {
			applicator.appendLogMsg("Failed to apply function at address " + address.toString() +
				"; attempting to use possible existing function");
			return applicator.getProgram().getListing().getFunctionAt(address);
		}
		return funCmd.getFunction();
	}

	/**
	 * Returns label to apply or null if label excluded
	 * @return label to process or null
	 */
	private String getLabel() {
		if (!applicator.getPdbApplicatorOptions().applyInstructionLabels()) {
			return null;
		}
		// Place compiler generated symbols (e.g., $LN9) within containing function when possible
		String label = symbol.getName();
		Matcher m =
			applicator.getPdbApplicatorOptions().excludeInstructionLabelsPattern().matcher(label);
		if (m.find()) {
			return null;
		}
		return label;
	}
}
