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

import java.util.HashMap;
import java.util.Map;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.util.bin.format.pdb2.pdbreader.MsSymbolIterator;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Abstract applier for symbols that need block context.
 * <p>
 * Note that this class as well as its children all need to be massaged to find the appropriate
 *  mechanisms to do the work.  Whether all children belong under this class or not is a question,
 *  and whether this current class name is appropriate is all in question.  Even whether
 *  this class is for nesting or more for functions is unknown... perhaps two of the children
 *  that do functions should have an intermediate parent (for functions) and the other
 *  (SeparatedCode) might be a direct child??? TODO, TODO, TODO
 */
public abstract class AbstractBlockContextApplier extends MsSymbolApplier
		implements DeferrableFunctionSymbolApplier, NestingSymbolApplier {

	protected BlockNestingContext context;
	protected long specifiedFrameSize = 0;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 */
	public AbstractBlockContextApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	void initContext() {
		context = new BlockNestingContext(applicator);
	}

	@Override
	public void beginBlock(Address startAddress, String name, long length) {
		context.beginBlock(startAddress, name, length);
	}

	@Override
	public void endBlock() {
		context.endBlock();
	}

	/**
	 * Set the specified frame size.
	 * @param specifiedFrameSize the frame size.
	 */
	void setSpecifiedFrameSize(long specifiedFrameSize) {
		this.specifiedFrameSize = specifiedFrameSize;
	}

	protected boolean notDone(BlockNestingContext blockNestingContext, MsSymbolIterator iter) {
		return blockNestingContext.notDone() && iter.hasNext();
	}

	protected boolean processEndSymbol(long endOffset, MsSymbolIterator iter) {

		// Jump to what should be the END symbol, but this might not be necessary, depending on
		//  what the caller is doing; for instance, if already doing an initGetByOffset() from
		//  "globals" offsets, then unnecessary, but it is safer that we do it here for now.
		iter.initGetByOffset(endOffset);

		AbstractMsSymbol subSymbol = iter.peek();
		boolean success = (subSymbol instanceof EndMsSymbol endSymbol);
		if (success) {
			iter.next();
		}
		else {
			applicator.appendLogMsg("PDB: Expecting EndMsSymbol termation of function but found " +
				subSymbol.getClass().getSimpleName());
		}
		return success;
	}

	protected void deferredProcessing(MsSymbolIterator iter, String name, Address address,
			Address blockAddress, long length)
			throws CancelledException, PdbException {

		long currentFrameSize = 0;

//		symbolBlockNestingLevel = 0;
//		BlockCommentsManager comments = new BlockCommentsManager();
//		currentBlockAddress = null;

		initContext();

		context.beginBlock(blockAddress, name, length);

//		TaskMonitor monitor = applicator.getCancelOnlyWrappingMonitor();
//		RegisterChangeCalculator registerChangeCalculator =
//			new RegisterChangeCalculator(symbol, function, monitor);

//		// TODO: need to decide how/where these get passed around... either we pass the function
//		//  around or pass things in the blockNestingContext or other
//		int baseParamOffset = VariableUtilities.getBaseStackParamOffset(function_x);
//		long currentFrameSize = 0;

//		boolean foundUnsupported = false;
		while (notDone(context, iter)) {
			applicator.checkCancelled();
			AbstractMsSymbol subSymbol = iter.peek();

			// TODO: msSymbol, subSymbol, comments, currentFrameSize, baseParmOffset

			MsSymbolApplier applier = applicator.getSymbolApplier(subSymbol, iter);
			if (applier instanceof NestableSymbolApplier nestingApplier) {
				nestingApplier.applyTo(this, iter);
			}
			else {
				applicator.getPdbApplicatorMetrics().witnessNonNestableSymbolType(subSymbol);
//				foundUnsupported = true;
				iter.next();
			}
		}
//		if (foundUnsupported) {
//			pdbLogAndInfoMessage(this, "One or or more non-nestable symbols skipped for: " + name);
//		}

		// comments
		//TODO: deal with specifiedAddress vs. address... do we still want to do any of this
//		long addressDelta = address_x.subtract(specifiedAddress_x);
//		blockNestingContext.getComments().applyTo(applicator.getProgram(), addressDelta);
		context.getComments().applyTo(applicator.getProgram(), 0);

//		// line numbers
//		// TODO: not done yet
////	ApplyLineNumbers applyLineNumbers = new ApplyLineNumbers(pdbParser, xmlParser, program);
////	applyLineNumbers.applyTo(monitor, log);

	}

	abstract long getStartOffset();

	abstract long getEndOffset();

	//==============================================================================================
	protected static class RegisterChangeCalculator {

		private Map<Register, Integer> registerChangeByRegisterName = new HashMap<>();
		private CallDepthChangeInfo callDepthChangeInfo;
		private Address debugStart;

		RegisterChangeCalculator(AbstractProcedureMsSymbol procedureSymbol,
				Function function, TaskMonitor monitor) throws CancelledException {
			callDepthChangeInfo = createCallDepthChangInfo(procedureSymbol, function, monitor);
		}

		private CallDepthChangeInfo createCallDepthChangInfo(
				AbstractProcedureMsSymbol procedureSymbol, Function function, TaskMonitor monitor)
				throws CancelledException {
			if (procedureSymbol == null) {
				return null;
			}
			Register frameReg = function.getProgram().getCompilerSpec().getStackPointer();
			Address entryAddr = function.getEntryPoint();
			debugStart = entryAddr.add(procedureSymbol.getDebugStartOffset());
			AddressSet scopeSet = new AddressSet();
			scopeSet.addRange(entryAddr, debugStart);
			return new CallDepthChangeInfo(function, scopeSet, frameReg, monitor);
		}

		Integer getRegChange(DefaultPdbApplicator applicator, Register register) {
			if (callDepthChangeInfo == null || register == null) {
				return null;
			}
			Integer change = registerChangeByRegisterName.get(register);
			if (change != null) {
				return change;
			}
			change = callDepthChangeInfo.getRegDepth(debugStart, register);
			registerChangeByRegisterName.put(register, change);
			return change;
		}

	}

}
