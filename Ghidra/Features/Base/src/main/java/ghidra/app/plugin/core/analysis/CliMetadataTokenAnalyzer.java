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
package ghidra.app.plugin.core.analysis;

import java.io.IOException;

import ghidra.app.services.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.pe.cli.CliMetadataRoot;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTableRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMethodDef.CliMethodDefRow;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds CLI metadata tokens and renders them significantly more useful to the human user versus the CLI Virtual Execution System.
 */
public class CliMetadataTokenAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "CLI Metadata Token Analyzer"; // Analyzer dialog chokes if '.' is in the name (doesn't show up at all, or ignores prototype flag, etc.)
	private static final String DESCRIPTION =
		"Takes CLI metadata tokens from their table/index form and gives a more useful representation.";

	public CliMetadataTokenAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.CODE_ANALYSIS);
		setPrototype();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return program.getLanguage()
				.getLanguageDescription()
				.getLanguageID()
				.getIdAsString()
				.contains("CLI");
	}

	@Override
	public boolean canAnalyze(Program program) {
		return getDefaultEnablement(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Symbol metadataRootSymbol = SymbolUtilities.getExpectedLabelOrFunctionSymbol(program,
			CliMetadataRoot.NAME, err -> log.appendMsg(getName(), err));

		if (metadataRootSymbol == null) {
			String message = "CLI Metadata Root Symbol not found.";
			log.appendMsg(getName(), message);
			log.setStatus(message);
			return false;
		}
		Address metadataRootAddr = metadataRootSymbol.getAddress();
		ByteProvider bytes = new MemoryByteProvider(program.getMemory(), metadataRootAddr);
		BinaryReader reader = new BinaryReader(bytes, !program.getLanguage().isBigEndian());

		boolean success = false;
		try {
			CliMetadataRoot metadataRoot = new CliMetadataRoot(reader, 0);
			metadataRoot.parse();

			CliStreamMetadata metadataStream = metadataRoot.getMetadataStream();

			success = processManagedInstructions(program, set, monitor, log, metadataRoot);
		}
		catch (IOException e) {
			String message = e.toString();
			log.appendMsg(getName(), message);
			log.setStatus(message);
			success = false;
		}

		return success;
	}

	private boolean processManagedInstructions(Program program, AddressSetView set,
			TaskMonitor monitor, MessageLog log, CliMetadataRoot metadataRoot)
			throws CancelledException {
		// Determine if each instruction has something we should fix up.
		// Note that we use endsWith() instead of equals() because instructions can have prefixes.
		CliStreamMetadata metadataStream = metadataRoot.getMetadataStream();
		InstructionIterator instIter = program.getListing().getInstructions(set, true);
		while (instIter.hasNext()) {
			try {
				Instruction inst = instIter.next();
				/* Base Instructions (Partition II.3) */
				if (inst.getMnemonicString().endsWith("ldstr")) {
					processUserString(metadataStream, inst);
				}
				else if (inst.getMnemonicString().endsWith("call")) {
					processControlFlowInstruction(program, metadataStream, inst,
						RefType.UNCONDITIONAL_CALL);
				}
				else if (inst.getMnemonicString().endsWith("calli")) {
					processControlFlowInstruction(program, metadataStream, inst,
						RefType.COMPUTED_CALL); // TODO: computed?
				}
				else if (inst.getMnemonicString().endsWith("jmp")) {
					processControlFlowInstruction(program, metadataStream, inst,
						RefType.UNCONDITIONAL_JUMP);
				}
				else if (inst.getMnemonicString().endsWith("ldftn")) {
					processGenericMetadataToken(metadataStream, inst);
					// TODO: how to say a method pointer is pushed onto the stack...
				}
				/* Object Model Instructions */
				else if (inst.getMnemonicString().endsWith("box") ||
					inst.getMnemonicString().endsWith("castclass") ||
					inst.getMnemonicString().endsWith("cpobj") ||
					inst.getMnemonicString().endsWith("initobj") ||
					inst.getMnemonicString().endsWith("isinst") ||
					inst.getMnemonicString().endsWith("ldelem") ||
					inst.getMnemonicString().endsWith("ldelema") ||
					inst.getMnemonicString().endsWith("ldfld") ||
					inst.getMnemonicString().endsWith("ldflda") ||
					inst.getMnemonicString().endsWith("ldobj") ||
					inst.getMnemonicString().endsWith("ldsfld") ||
					inst.getMnemonicString().endsWith("ldsflda") ||
					inst.getMnemonicString().endsWith("ldtoken") ||
					inst.getMnemonicString().endsWith("mkrefany") ||
					inst.getMnemonicString().endsWith("newarr") ||
					inst.getMnemonicString().endsWith("newobj") ||
					inst.getMnemonicString().endsWith("refanyval") ||
					inst.getMnemonicString().endsWith("sizeof") ||
					inst.getMnemonicString().endsWith("stelem") ||
					inst.getMnemonicString().endsWith("stfld") ||
					inst.getMnemonicString().endsWith("stobj") ||
					inst.getMnemonicString().endsWith("stsfld") ||
					inst.getMnemonicString().endsWith("unbox") ||
					inst.getMnemonicString().endsWith("unbox.any")) {
					processObjectModelInstruction(program, metadataStream, inst);
				}
				else if (inst.getMnemonicString().endsWith("callvirt")) {
					processControlFlowInstruction(program, metadataStream, inst,
						RefType.COMPUTED_CALL);
					// TODO: Computed call because this is a virtual function on an object
				}
				else if (inst.getMnemonicString().endsWith("constrained")) {
					CliAbstractTableRow tableRow = getRowForMetadataToken(metadataStream, inst);
					markMetadataRow(inst, tableRow, "Next instr type req'd to be: ", "",
						metadataStream);
				}
				else if (inst.getMnemonicString().endsWith("ldvirtfn")) {
					processObjectModelInstruction(program, metadataStream, inst);
					// TODO: ldvirtfn puts virtual method pointer on stack, see above for ldftn
				}
			}
			catch (Exception e) {
				e.printStackTrace();
				// TODO:
			}
		}

		return true;
	}

	private void processGenericMetadataToken(CliStreamMetadata metaStream, Instruction inst) {
		CliAbstractTableRow tableRow = getRowForMetadataToken(metaStream, inst);
		markMetadataRow(inst, tableRow, metaStream);
	}

	private void processObjectModelInstruction(Program program, CliStreamMetadata metaStream,
			Instruction inst) {
		CliAbstractTableRow tableRow = getRowForMetadataToken(metaStream, inst);
		markMetadataRow(inst, tableRow, "", " (Object Model Instruction)", metaStream);
	}

	private void processUserString(CliStreamMetadata metaStream, Instruction inst) {
		Scalar strIndexOp = (Scalar) inst.getOpObjects(0)[0];

		int strIndex = (int) strIndexOp.getUnsignedValue();

		inst.setComment(CodeUnit.EOL_COMMENT,
			"\"" + metaStream.getUserStringsStream().getUserString(strIndex) + "\"");
	}

	private void processControlFlowInstruction(Program program, CliStreamMetadata metaStream,
			Instruction inst, RefType refType) {
		CliAbstractTableRow tableRow = getRowForMetadataToken(metaStream, inst);
		markMetadataRow(inst, tableRow, metaStream);
		if (tableRow instanceof CliMethodDefRow) {
			// TODO: Add a control flow reference ideally
			// Op 0 => table, Op 1 => call destination?
			// inst.addOperandReference(OP_INDEX, DEST_ADDR, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS); // TODO: unconditional call?
			// program.getReferenceManager().addMemoryReference(INST_ADDR, DEST_ADDR, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);
			CliMethodDefRow methodDef = (CliMethodDefRow) tableRow;
			if (methodDef.RVA != 0) {
				Address destAddr =
					program.getAddressFactory().getDefaultAddressSpace().getAddress(methodDef.RVA); // TODO: RVA isn't the right address to use in raw binary format. Don't know in PE.
				inst.addOperandReference(1, destAddr, refType, SourceType.ANALYSIS);
			}
		}
	}

	private CliAbstractTableRow getRowForMetadataToken(CliStreamMetadata metaStream,
			Instruction inst) {
		Object ops[] = inst.getOpObjects(0);
		Scalar tableOp = (Scalar) ops[0];
		Scalar indexOp = (Scalar) ops[1];
		int table = (int) tableOp.getUnsignedValue();
		int index = (int) indexOp.getUnsignedValue();
		CliAbstractTableRow tableRow = metaStream.getTable(table).getRow(index);
		return tableRow;
	}

	private void markMetadataRow(Instruction inst, CliAbstractTableRow tableRow,
			String prependComment, String appendComment, CliStreamMetadata stream) {
		inst.setComment(CodeUnit.EOL_COMMENT, String.format("%s%s%s", prependComment,
			tableRow.getShortRepresentation(stream), appendComment));
	}

	private void markMetadataRow(Instruction inst, CliAbstractTableRow tableRow,
			CliStreamMetadata stream) {
		markMetadataRow(inst, tableRow, "", "", stream);
	}
}
