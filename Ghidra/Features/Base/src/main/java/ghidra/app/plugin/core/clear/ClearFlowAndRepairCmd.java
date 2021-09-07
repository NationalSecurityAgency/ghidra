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
package ghidra.app.plugin.core.clear;

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerContextImpl;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ClearFlowAndRepairCmd extends BackgroundCommand {

	private static final int FALLTHROUGH_SEARCH_LIMIT = 12;

	private AddressSetView startAddrs;
	private boolean clearData;
	private boolean clearLabels;
	private boolean clearComputedPtrRefs = true;
	private boolean clearOffcut = true;
	private boolean repair;
	private boolean repairFunctions;

	private AddressSet clearSet;
	private AddressSetView protectedSet;

	public ClearFlowAndRepairCmd(Address startAddr, boolean clearData, boolean clearLabels,
			boolean repair) {
		this(new AddressSet(startAddr, startAddr), clearData, clearLabels, repair);
	}

	public ClearFlowAndRepairCmd(AddressSetView startAddrs, boolean clearData, boolean clearLabels,
			boolean repair) {
		this(startAddrs, null, clearData, clearLabels, repair);
	}

	public ClearFlowAndRepairCmd(AddressSetView startAddrs, AddressSetView protectedSet,
			boolean clearData, boolean clearLabels, boolean repair) {
		super("Clear Flow", false, true, true);
		this.startAddrs = startAddrs;
		this.protectedSet = (protectedSet == null ? new AddressSet() : protectedSet);
		this.clearData = clearData;
		this.clearLabels = clearLabels;
		this.repair = repair;
		this.repairFunctions = repair;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		try {
			monitor.setMessage("Examining code flow...");

			Program program = (Program) obj;
			Listing listing = program.getListing();

			Stack<Address> todoStarts = new Stack<>();
			CodeUnitIterator cuIter = listing.getCodeUnits(startAddrs, true);
			// if no instructions are in the address set off the bat, adjust it
			//   to include the starts of any instructions that might fall
			//   within the selection.
			if (!cuIter.hasNext()) {
				AddressRangeIterator rangeIter = startAddrs.getAddressRanges();
				AddressSet expandedSet = new AddressSet(startAddrs);
				while (rangeIter.hasNext()) {
					AddressRange range = rangeIter.next();
					CodeUnit cu = listing.getCodeUnitContaining(range.getMinAddress());
					if (cu != null) {
						expandedSet.addRange(cu.getMinAddress(), cu.getMaxAddress());
					}
				}
				cuIter = listing.getCodeUnits(expandedSet, true);
				startAddrs = expandedSet;
			}

			clearSet = new AddressSet();

			while (cuIter.hasNext()) {
				monitor.checkCanceled();
				CodeUnit cu = cuIter.next();
				if (cu instanceof Instruction) {
					Instruction instr = (Instruction) cu;
					Address ffAddr = instr.getFallFrom();
					if (ffAddr != null && startAddrs.contains(ffAddr)) {
						continue; // skip since it will be picked-up by flow
					}
				}
				else {
					Data d = (Data) cu;
					if (!d.isDefined()) {
						if (startAddrs.contains(d.getAddress())) {
							// handle failed disassembly and pretend we cleared it
							clearSet.add(d.getAddress());
						}
						continue; // skip undefined data
					}
					if (d.isPointer() && clearComputedPtrRefs) {
						clearComputedTableRefs(d, monitor);
					}
				}
				todoStarts.push(cu.getMinAddress());
			}

			Address doNotRepairAddr = todoStarts.size() == 1 ? (Address) todoStarts.get(0) : null;

			AddressSet clearDataSet = new AddressSet();
			HashSet<Address> ptrDestinations = new HashSet<>();

			while (!todoStarts.isEmpty()) {
				monitor.checkCanceled();
				Address addr = todoStarts.pop();
				if (clearSet.contains(addr)) {
					continue;
				}

				// Don't mess with protected locations
				if (protectedSet.contains(addr)) {
					continue;
				}

				CodeUnit cu = listing.getCodeUnitAt(addr);
				if (cu instanceof Instruction) {
					AddressSetView clearInstrSet =
						findInstructionFlow(program, addr, clearSet, todoStarts, monitor);
					clearSet.add(clearInstrSet);
					addDereferencedInstructionStarts(program, todoStarts, clearSet, clearInstrSet,
						monitor);
				}
				else {
					Data d = (Data) cu;
					if (!d.isDefined()) {
						continue;
					}
					AddressSet dataRange = new AddressSet(d.getMinAddress(), d.getMaxAddress());
					clearSet.add(dataRange);
					clearDataSet.add(dataRange);
					Reference[] refs = d.getReferencesFrom();
					for (Reference ref : refs) {
						ptrDestinations.add(ref.getToAddress());
					}
					addDereferencedInstructionStarts(program, todoStarts, clearSet, dataRange,
						monitor);
				}
			}

			if (!clearData) {
				// Do not clear data
				clearSet.delete(clearDataSet);
				// not clearing data, make sure bad bookmarks cleared
				// from code flow into defined data
				clearBadBookmarks(program, clearDataSet, monitor);
			}

			clearSet.delete(protectedSet);

			ClearOptions opts = new ClearOptions(true);
			opts.setClearSymbols(clearLabels);

			ClearCmd clear = new ClearCmd(clearSet, opts);
			clear.applyTo(obj, monitor);

			if (clearData && clearLabels) {
				// Clear dereferenced symbols
				SymbolTable symTable = program.getSymbolTable();
				Iterator<Address> iter = ptrDestinations.iterator();
				while (iter.hasNext()) {
					monitor.checkCanceled();
					Address addr = iter.next();
					Symbol[] syms = symTable.getSymbols(addr);
					for (Symbol sym : syms) {
						if (sym.getSource() == SourceType.DEFAULT) {
							break;
						}
						if (sym.hasReferences()) {
							continue;
						}
						sym.delete();
					}
				}
			}

			if (repair) {
				repairFlowsInto(program, clearSet, doNotRepairAddr, monitor);
			}
			if (repairFunctions) {
				repairFunctions(program, clearSet, monitor);
				monitor.setIndeterminate(false);
			}

			return true;
		}
		catch (CancelledException e) {
			clearSet = null;
		}
		return false;
	}

	/**
	 * Find and clear computed references produced as a result of the specified
	 * pointer when contained within a pointer table.
	 * @param d pointer
	 */
	private void clearComputedTableRefs(Data d, TaskMonitor monitor) throws CancelledException {

		Program p = d.getProgram();
		Listing listing = p.getListing();
		ReferenceManager refMgr = p.getReferenceManager();
		Address destAddr = d.getAddress(0);

		ReferenceIterator refIter = refMgr.getReferencesTo(destAddr);
		while (refIter.hasNext()) {
			monitor.checkCanceled();
			Reference ref = refIter.next();
			RefType refType = ref.getReferenceType();
			if (refType instanceof FlowType) {
				Instruction instr = listing.getInstructionAt(ref.getFromAddress());
				if (instr == null || instr.getFlowType().isComputed() ||
					((FlowType) refType).isComputed()) {
					refMgr.delete(ref);
				}
			}
		}
	}

	/**
	 * Identify additional dereferenced instruction starts which should be cleared. 
	 * @param program
	 * @param starts stack to which dereferenced instruction starts will be added
	 * @param clearSet all addresses intended to be cleared, should also contain refFromSet
	 * @param refFromSet address set over which from references should be checked
	 * @param monitor
	 * @throws CancelledException 
	 */
	private void addDereferencedInstructionStarts(Program program, Stack<Address> starts,
			AddressSetView clearSet, AddressSetView refFromSet, TaskMonitor monitor)
			throws CancelledException {

		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();

		AddressIterator fromAddrIter = refMgr.getReferenceSourceIterator(refFromSet, true);
		while (fromAddrIter.hasNext()) {
			monitor.checkCanceled();

			Address fromAddr = fromAddrIter.next();

			// Check for data references which will result in unreferenced instructions
			Reference[] refs = refMgr.getReferencesFrom(fromAddr);
			for (Reference ref2 : refs) {
				Address toAddr = ref2.getToAddress();

				if (clearSet.contains(toAddr)) {
					continue; // destination already marked for clearing
				}

				// Check all references to the same destination
				// If all sources are marked for clearing, add destination to todoStarts
				Instruction instr = listing.getInstructionAt(toAddr);
				if (instr == null) {
					if (!this.clearData) {
						continue;
					}
					// no instruction, check if data is there
					Data data = listing.getDefinedDataAt(toAddr);
					if (data == null) {
						continue; // instruction not found at destination
					}
				}
				boolean clearIt = true;
				ReferenceIterator refIter = refMgr.getReferencesTo(toAddr);
				while (refIter.hasNext()) {
					monitor.checkCanceled();
					Reference ref = refIter.next();
					if (!clearSet.contains(ref.getFromAddress())) {
						clearIt = false;
						break;
					}
				}
				// if there is no instruction falling into this one, clearIt too
				if (clearIt && (instr == null || instr.getFallFrom() == null)) {
					starts.push(toAddr);
				}
			}
		}

	}

	/**
	 * Attempt to repair context prior to disassembly by re-disassembly of the 
	 * existing instruction which flows to the disassembly start location.
	 * @param program
	 * @param fromInstrAddr existing instruction address to be used for
	 * context regeneration
	 * @param flowFallthrough true if fall-through location is clear and
	 * is the intended disassembly start location, else only the future
	 * flow context state is needed.
	 * @param context disassembly context.
	 */
	private void repairFlowContextFrom(Program program, Address fromInstrAddr,
			DisassemblerContextImpl context) {

		Instruction instr = program.getListing().getInstructionAt(fromInstrAddr);
		if (instr == null) {
			return;
		}

		context.flowStart(fromInstrAddr);
		try {
			// re-parse instruction to regenerate future context state
			program.getLanguage().parse(instr, context, instr.isInDelaySlot());
		}
		catch (Exception e) {
			return;
		}
		finally {
			context.flowAbort();
		}
	}

	/**
	 * Regenerate future context flow state prior to re-disassembly of branch/call 
	 * destinations. 
	 * NOTE: behavior is unaffected by flow references
	 * @param program
	 * @param fromInstrAddr existing instruction address to be used for
	 * context regeneration
	 * @param context disassembly context.
	 */
	private void repairFallThroughContextFrom(Program program, Address fromInstrAddr,
			DisassemblerContextImpl context) {

		Instruction instr = program.getListing().getInstructionAt(fromInstrAddr);
		if (instr == null || !instr.hasFallthrough()) {
			return;
		}
		Address fallThroughAddr = instr.getFallThrough();

		context.flowStart(fromInstrAddr);
		try {
			// re-parse instruction to regenerate fall-through context
			program.getLanguage().parse(instr, context, instr.isInDelaySlot());
			RegisterValue contextValue = context.getFlowContextValue(fallThroughAddr, true);
			program.getProgramContext()
					.setRegisterValue(fallThroughAddr, fallThroughAddr, contextValue);
		}
		catch (Exception e) {
			return;
		}
		finally {
			context.flowAbort();
		}
	}

	/**
	 * Repair disassembly in and around the cleared area.
	 * @return set of disassembled addresses
	 */
	private void repairFlowsInto(Program program, AddressSetView clearSet, Address ignoreStart,
			TaskMonitor monitor) throws CancelledException {

		AddressSetView disAddrs = repairFallThroughsInto(program, clearSet, ignoreStart, monitor);

		AddressSet disassemblePoints = new AddressSet();
		AddressSet dataRefSet = new AddressSet();

		ProgramContext programContext = program.getProgramContext();
		Register contextReg = programContext.getBaseContextRegister();
		DisassemblerContextImpl seedContext = null;

		ReferenceManager refMgr = program.getReferenceManager();
		if (disAddrs != null) {
			clearSet = clearSet.subtract(disAddrs);
		}
		AddressIterator addrIter = refMgr.getReferenceDestinationIterator(clearSet, true);
		while (addrIter.hasNext()) {
			monitor.checkCanceled();
			Address addr = addrIter.next();
			ReferenceIterator refIter = refMgr.getReferencesTo(addr);

			Address dataRefAddr = null;
			while (refIter.hasNext()) {
				monitor.checkCanceled();
				Reference ref = refIter.next();
				RefType refType = ref.getReferenceType();
				if (refType.isFlow()) {
					if (addr.equals(ignoreStart)) {
						continue;
					}
					disassemblePoints.addRange(addr, addr);
					if (contextReg != Register.NO_CONTEXT) {
						if (seedContext == null) {
							seedContext = new DisassemblerContextImpl(programContext);
						}
						repairFlowContextFrom(program, ref.getFromAddress(), seedContext);
// TODO: context which contains future flow states is never used by disassembler 
// and does not affect stored program context - need to use within disassembler to leverage
// repaired future context states.  This is also done inconsistent with fall-through repair.
					}
					break;
				}
				else if (dataRefAddr == null) {
					if (addr.equals(ignoreStart) && !refType.isRead() && !refType.isWrite()) {
						continue;
					}
					// Remember single data reference for possible analysis
					dataRefAddr = ref.getFromAddress();
				}
			}
			if (dataRefAddr != null && !disassemblePoints.contains(addr)) {
				dataRefSet.addRange(dataRefAddr, dataRefAddr);
			}
		}

		// get any in the clear set that were entry points
		AddressIterator aiter = clearSet.getAddresses(true);
		while (aiter.hasNext()) {
			monitor.checkCanceled();
			Address addr = aiter.next();
			if (program.getSymbolTable().isExternalEntryPoint(addr)) {
				disassemblePoints.addRange(addr, addr);
			}
		}

		// NOTE: This had previously been switched to use Disassembler - if this
		// gets switched-back again, please make a not of why DisassembleCommand is not suitable.

		DisassembleCommand cmd = new DisassembleCommand(disassemblePoints, null);
		cmd.setSeedContext(seedContext);
		cmd.applyTo(program, monitor);

		monitor.checkCanceled();

		// Analyze new data reference points (DisassembleCommand has already analyzed code)
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		analysisMgr.codeDefined(dataRefSet);
		analysisMgr.startAnalysis(monitor);
	}

	/**
	 * Repair fall-through flows which fall into the cleared area.
	 */
	private AddressSetView repairFallThroughsInto(Program program, AddressSetView clearSet,
			Address ignoreStart, TaskMonitor monitor) throws CancelledException {

		AddressSet disassemblePoints = new AddressSet();
		//AddressSet alreadyCleared = new AddressSet(program.getAddressFactory());

		Listing listing = program.getListing();

		ProgramContext programContext = program.getProgramContext();
		Register contextReg = programContext.getBaseContextRegister();
		DisassemblerContextImpl seedContext = null;

		AddressRangeIterator rangeIter = clearSet.getAddressRanges();
		while (rangeIter.hasNext()) {
			monitor.checkCanceled();
			AddressRange range = rangeIter.next();
			Address addr = range.getMinAddress();
			int searchCnt = 0;

			// Search backward for incomplete fallthrough
			// A fallthrough to ignoreStart is ignored
			while (searchCnt < FALLTHROUGH_SEARCH_LIMIT && (addr = addr.previous()) != null) {
				CodeUnit cu = listing.getCodeUnitAt(addr);
				if (cu == null) {
					if (!program.getMemory().contains(addr)) {
						break;
					}
					continue; // in middle of code unit
				}
				if (cu instanceof Instruction) {
					Instruction instr = (Instruction) cu;
					if (instr.isInDelaySlot()) {
						continue;
					}
					Address ftAddr = instr.getFallThrough();
					if (ftAddr != null && (ignoreStart == null || !ftAddr.equals(ignoreStart))) {
//                        alreadyCleared.addRange(ftAddr, addr);
						disassemblePoints.addRange(ftAddr, ftAddr);
						if (contextReg != Register.NO_CONTEXT) {
							if (seedContext == null) {
								seedContext = new DisassemblerContextImpl(programContext);
							}
							repairFallThroughContextFrom(program, instr.getMinAddress(),
								seedContext);
						}
					}
					break;
				}
				Data d = (Data) cu;
				if (d.isDefined()) {
					break;
				}
				++searchCnt;
			}
		}
//         clearSet.add(alreadyCleared);

		// Get rid of any bad bookmarks at seed points, will be put back if they are still bad.
		program.getBookmarkManager()
				.removeBookmarks(disassemblePoints, BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY, monitor);

		// Disassemble fallthrough reference points
		DisassembleCommand cmd = new DisassembleCommand(disassemblePoints, null);
		cmd.setSeedContext(seedContext);
		cmd.applyTo(program, monitor);

		return cmd.getDisassembledAddressSet();
	}

	void repairFunctions(Program program, AddressSetView clearSet, TaskMonitor monitor)
			throws CancelledException {

		FunctionManager fnMgr = program.getFunctionManager();

		MultEntSubModel subModel = new MultEntSubModel(program);
		CodeBlockIterator subIter = subModel.getCodeBlocksContaining(clearSet, monitor);
		while (subIter.hasNext()) {
			CodeBlock sub = subIter.next();
			HashSet<Address> starts = new HashSet<>(Arrays.asList(sub.getStartAddresses()));

			Iterator<Function> fnIter = fnMgr.getFunctionsOverlapping(sub);
			while (fnIter.hasNext()) {
				monitor.checkCanceled();
				Function f = fnIter.next();
				if (!starts.contains(f.getEntryPoint())) {
					Msg.warn(this,
						"WARNING! Removing function with bad body at " + f.getEntryPoint());
					fnMgr.removeFunction(f.getEntryPoint());
				}
			}

			fnIter = fnMgr.getFunctionsOverlapping(sub);
			while (fnIter.hasNext()) {
				monitor.checkCanceled();
				Function f = fnIter.next();
				if (starts.remove(f.getEntryPoint())) {
					AddressSetView oldBody = f.getBody();
					AddressSet newBody = new AddressSet(oldBody.subtract(clearSet));
					newBody.add(CreateFunctionCmd.getFunctionBody(program, f.getEntryPoint()));
					if (!oldBody.equals(newBody)) {
						Msg.warn(this,
							"WARNING! Repairing body of function at " + f.getEntryPoint());
						try {
							f.setBody(newBody);
						}
						catch (OverlappingFunctionException e) {
							Msg.error(this,
								"... function body repair failed due to overlap with another function: " +
									f.getEntryPoint());
						}
					}
				}
			}

			Iterator<Address> entryIter = starts.iterator();
			while (entryIter.hasNext()) {
				monitor.checkCanceled();
				Address entry = entryIter.next();
				CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
				cmd.applyTo(program, monitor);
			}
		}
	}

	private static class BlockVertex {
		final CodeBlock block;
		final Set<BlockVertex> srcVertices = new HashSet<>();
		final Set<BlockVertex> destVertices = new HashSet<>();

		BlockVertex(CodeBlock block) {
			this.block = block;
		}
	}

	/**
	 * Follow code flow and identify address set to be cleared.
	 * If offcut code is encountered, it will be cleared immediately.
	 * @param program
	 * @param firstAddr
	 * @param clearSet code unit areas already decided to clear
	 * @param todoStarts
	 * @param monitor
	 * @return
	 * @throws CancelledException
	 */
	private AddressSetView findInstructionFlow(Program program, Address firstAddr,
			AddressSetView clearSet, Stack<Address> todoStarts, TaskMonitor monitor)
			throws CancelledException {

		AddressSet blockSet = new AddressSet();
		Listing listing = program.getListing();
		SymbolTable symbolTable = program.getSymbolTable();

		if (clearOffcut) {
			// Check for initial offcut instruction
			Instruction prevInstr = listing.getInstructionBefore(firstAddr);
			if (prevInstr != null && firstAddr.compareTo(prevInstr.getMaxAddress()) <= 0) {
				clearOffcutFlow(listing.getInstructionAt(firstAddr), todoStarts, monitor);
				return blockSet;
			}
		}

		Hashtable<Address, BlockVertex> vertexMap = new Hashtable<>();

		SimpleBlockModel blockModel = new SimpleBlockModel(program);
		Stack<BlockVertex> todoVertices = new Stack<>();

		Set<Address> destAddrs = new HashSet<>(); // re-usable set for collecting block destination addrs

		// Establish start vertex within flow graph
		CodeBlock startBlock = blockModel.getFirstCodeBlockContaining(firstAddr, monitor);
		blockSet.add(startBlock);
		BlockVertex startVertex = new BlockVertex(startBlock);
		vertexMap.put(startBlock.getMinAddress(), startVertex);
		todoVertices.push(startVertex);

		boolean neverSnipStartBlock = (startAddrs.contains(firstAddr));

		// Follow start block flow and build graph
		while (!todoVertices.isEmpty()) {
			monitor.checkCanceled();
			BlockVertex fromVertex = todoVertices.pop();
			CodeBlock fromBlock = fromVertex.block;
			if (protectedSet.contains(fromBlock.getMinAddress())) {
				continue;
			}
			fromBlock = adjustBlockForSplitProtectedBlock(program, blockModel,
				fromBlock.getFirstStartAddress(), fromBlock);

			// HOT SPOT - getDestinations()
			CodeBlockReferenceIterator blockRefIter = fromBlock.getDestinations(monitor);
			if (clearOffcut) {
				findDestAddrs(fromBlock, destAddrs); // Needed for detecting offcut flows
			}
			while (blockRefIter.hasNext()) {
				monitor.checkCanceled();
				CodeBlockReference cbRef = blockRefIter.next();

				Address blockAddr = cbRef.getReference();
				if (protectedSet.contains(blockAddr)) {
					continue;
				}
				if (clearSet.contains(blockAddr)) {
					continue;
				}
				CodeBlock destBlock = cbRef.getDestinationBlock();
				if (blockAddr.equals(destBlock.getFirstStartAddress())) {
					destBlock = adjustBlockForSplitProtectedBlock(program, blockModel, blockAddr,
						destBlock);
				}
				if (neverSnipStartBlock && destBlock.equals(startBlock)) {
					continue; // do not allow incoming edges to startBlock vertex
				}

				BlockVertex destVertex = vertexMap.get(blockAddr);
				if (destVertex == null) {
					if (listing.getInstructionAt(blockAddr) == null) {
						continue; // do not include data
					}
					Symbol s = symbolTable.getPrimarySymbol(blockAddr);
					if (s != null && s.getSymbolType() == SymbolType.FUNCTION) {
						SourceType source = s.getSource();
						if (source == SourceType.USER_DEFINED || source == SourceType.IMPORTED) {
							continue; // keep imported or user-defined function
						}
					}

					if (clearOffcut && !destAddrs.contains(blockAddr)) {
						// Offcut flow was cleared - skip this block
						if (clearOffcutFlow(destBlock, todoStarts, monitor)) {
							continue;
						}
					}
					// TODO: check disassembly hint
					blockSet.add(destBlock);
					destVertex = new BlockVertex(destBlock);
					vertexMap.put(blockAddr, destVertex);
					todoVertices.push(destVertex);
				}
				// HOT SPOT - HashSet.add()
				fromVertex.destVertices.add(destVertex);
				destVertex.srcVertices.add(fromVertex);
			}
		}

		// If start address not start of block, never clear the first part of the block
		if (!firstAddr.equals(startBlock.getMinAddress())) {
			blockSet.deleteRange(startBlock.getMinAddress(), firstAddr.previous());
		}

		ReferenceManager refMgr = program.getReferenceManager();
		FunctionManager functionManager = program.getFunctionManager();
		Iterator<BlockVertex> vertexIter = vertexMap.values().iterator();
		while (vertexIter.hasNext()) {
			monitor.checkCanceled();
			BlockVertex v = vertexIter.next();
			if (v == startVertex || v.srcVertices.isEmpty()) {
				continue;
			}
			Address addr = v.block.getMinAddress();
			Instruction instr = listing.getInstructionAt(addr);
			Address fallFrom = instr.getFallFrom();
			if (fallFrom != null && !blockSet.contains(fallFrom)) {
				prune(v, blockSet);
			}
			else {
				ReferenceIterator refIter = refMgr.getReferencesTo(addr);

				// If there are no references, and there is a defined function inside this block
				//   That starts in this block, with no references to it, then this bad flow couldn't
				//   have created it.
				// TODO: maybe even just symbols with no refs to them should be snipped
				//       code starts at the symbol someone might have disassembled there.
				if (!refIter.hasNext() && functionManager.getFunctionAt(addr) != null) {
					prune(v, blockSet);
					continue;
				}
				while (refIter.hasNext()) {
					monitor.checkCanceled();
					Reference ref = refIter.next();
					Address fromAddr = ref.getFromAddress();
					RefType refType = ref.getReferenceType();
					if (refType.isFlow() && !blockSet.contains(fromAddr) &&
						!clearSet.contains(fromAddr)) {
						prune(v, blockSet);
						break;
					}
					// any addr which corresponds to a entry-point function should be snipped
					if (refType == RefType.EXTERNAL_REF &&
						functionManager.getFunctionAt(addr) != null) {
						prune(v, blockSet);
						break;
					}
				}
			}
		}

		if (repair) {
			clearBadBookmarks(program, blockSet, monitor);
		}

		return blockSet;
	}

	private CodeBlock adjustBlockForSplitProtectedBlock(Program program,
			SimpleBlockModel blockModel, Address blockAddr, CodeBlock blockToAdjust) {
		if (!protectedSet.isEmpty()) {
			AddressSet intersect = protectedSet.intersectRange(blockToAdjust.getMinAddress(),
				blockToAdjust.getMaxAddress());
			if (!intersect.isEmpty() && !intersect.getMinAddress().equals(blockAddr)) {
				Address[] entryPts = new Address[1];
				entryPts[0] = blockAddr;
				CodeBlock block = new CodeBlockImpl(blockModel, entryPts,
					new AddressSet(blockAddr, intersect.getMinAddress().subtract(1)));
				blockToAdjust = block;
			}
		}
		return blockToAdjust;
	}

	private boolean clearOffcutFlow(CodeBlock destBlock, Stack<Address> todoStarts,
			TaskMonitor monitor) throws CancelledException {
		Address blockEnd = destBlock.getMaxAddress();
		Address offcutStart = null;
		Instruction instr = null;
		Program program = destBlock.getModel().getProgram();
		Listing listing = program.getListing();
		InstructionIterator iter = listing.getInstructions(destBlock.getMinAddress(), true);
		while (iter.hasNext() && offcutStart == null) {
			monitor.checkCanceled();
			Instruction nextInstr = iter.next();
			Address nextInstrAddr = nextInstr.getMinAddress();
			if (nextInstrAddr.compareTo(blockEnd) > 0) {
				break;
			}
			if (instr != null && nextInstrAddr.compareTo(instr.getMaxAddress()) <= 0) {
				offcutStart = nextInstrAddr;
			}
			instr = nextInstr;
		}
		if (offcutStart == null) {
			return false;
		}
		clearOffcutFlow(instr, todoStarts, monitor);
		return true;
	}

	private void clearOffcutFlow(Instruction offcutInstr, Stack<Address> todoStarts,
			TaskMonitor monitor) throws CancelledException {

		// Follow offcut flow
		while (offcutInstr != null) {

			Program program = offcutInstr.getProgram();
			Listing listing = program.getListing();

			monitor.checkCanceled();

			// Record outgoing flows as new starts for clearing
			Reference[] refs = offcutInstr.getReferencesFrom();
			for (Reference ref : refs) {
				if (ref.getReferenceType().isFlow()) {
					todoStarts.add(ref.getToAddress());
				}
			}

			// Get fallthrough address
			Address ftAddr = offcutInstr.getFallThrough();

			if (repair) {
				clearBadBookmarks(program, offcutInstr.getMinAddress(), offcutInstr.getMaxAddress(),
					monitor);
			}

			// Clear offcut instruction
			listing.clearCodeUnits(offcutInstr.getMinAddress(), offcutInstr.getMinAddress(), false);

// TODO: addDereferencedInstructionStarts

			// Follow fallthrough
			offcutInstr = listing.getInstructionAt(ftAddr);
			if (offcutInstr != null) {
				Instruction prevInstr = listing.getInstructionBefore(offcutInstr.getMinAddress());
				if (prevInstr != null &&
					prevInstr.getMaxAddress().compareTo(offcutInstr.getMinAddress()) < 0) {
					offcutInstr = null; // end of offcut fallthrough
				}
			}
		}
	}

	public static void clearBadBookmarks(Program program, Address start, Address end,
			TaskMonitor monitor) throws CancelledException {
		AddressSet set = new AddressSet(start, end);
		program.getBookmarkManager()
				.removeBookmarks(set, BookmarkType.ERROR, Disassembler.ERROR_BOOKMARK_CATEGORY,
					monitor);
	}

	public static void clearBadBookmarks(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {

		BookmarkManager bookmarkMgr = program.getBookmarkManager();

		// Check data fall-through locations for bookmarks
		Listing listing = program.getListing();
		for (AddressRange range : set.getAddressRanges()) {
			monitor.checkCanceled();
			Address maxAddr = range.getMaxAddress();
			Instruction lastInstr = listing.getInstructionContaining(maxAddr);
			if (lastInstr == null) {
				continue;
			}
			Address nextAddr = lastInstr.getFallThrough();
			if (nextAddr == null) {
				continue;
			}
			if (listing.getDataContaining(nextAddr) != null) {
				Bookmark bookmark = bookmarkMgr.getBookmark(nextAddr, BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY);
				if (bookmark != null) {
					bookmarkMgr.removeBookmark(bookmark);
				}
			}
		}

		// Check any offcut flows that are not part of the cleared set
		//    This assumes that any bookmark at then end of a to reference from the
		//      cleared set is not a good bookmark.  Could test that there are no other refs to it
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator refIter = referenceManager.getReferenceSourceIterator(set, true);
		for (Address address : refIter) {
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			for (Reference reference : referencesFrom) {
				Address toAddr = reference.getToAddress();
				if (set.contains(toAddr)) {
					continue;
				}
				// if we aren't offcut, continue
				if (listing.getInstructionAt(toAddr) != null) {
					continue;
				}
				// no bookmark there, continue;
				if (program.getBookmarkManager().getBookmarks(toAddr).length == 0) {
					continue;
				}
				// not the right references
				int referenceCountTo = referenceManager.getReferenceCountTo(toAddr);
				if (referenceCountTo > 1) {
					// if more than one ref, must make sure all others are not data refs
					ReferenceIterator referencesTo = referenceManager.getReferencesTo(toAddr);
					int flowCount = 0;
					for (Reference referenceTo : referencesTo) {
						if (referenceTo.getReferenceType().isFlow()) {
							flowCount++;
						}
					}
					if (flowCount != 1) {
						continue;
					}
				}
				clearBadBookmarks(program, toAddr, toAddr, monitor);
			}

		}

		bookmarkMgr.removeBookmarks(set, BookmarkType.ERROR, Disassembler.ERROR_BOOKMARK_CATEGORY,
			monitor);
	}

	/**
	 * Clears destAddrs set and add all flow destination addresses into set.
	 */
	private void findDestAddrs(CodeBlock block, Set<Address> destAddrs) {
		destAddrs.clear();
		Listing listing = block.getModel().getProgram().getListing();
		Instruction instr = listing.getInstructionContaining(block.getMaxAddress());
		while (instr != null && instr.isInDelaySlot()) {
			Address ffAddr = instr.getFallFrom();
			instr = ffAddr != null ? listing.getInstructionAt(ffAddr) : null;
		}
		if (instr == null) {
			return;
		}
		Address ftAddr = instr.getFallThrough();
		if (ftAddr != null) {
			destAddrs.add(ftAddr);
		}
		Reference[] refs = instr.getReferencesFrom();
		for (Reference ref : refs) {
			if (ref.getReferenceType().isFlow()) {
				destAddrs.add(ref.getToAddress());
			}
		}
	}

	private void prune(BlockVertex v, AddressSet blockSet) {

		Stack<BlockVertex> pruneStack = new Stack<>();
		pruneStack.push(v);

		while (!pruneStack.isEmpty()) {

			v = pruneStack.pop();
			blockSet.delete(v.block);

			// Snip incoming edges
			Iterator<BlockVertex> iter = v.srcVertices.iterator();
			while (iter.hasNext()) {
				BlockVertex fromVertex = iter.next();
				fromVertex.destVertices.remove(v);
			}
			v.srcVertices.clear();

			// Add destinations to pruneStack
			iter = v.destVertices.iterator();
			while (iter.hasNext()) {
				pruneStack.push(iter.next());
			}
		}
	}
}
