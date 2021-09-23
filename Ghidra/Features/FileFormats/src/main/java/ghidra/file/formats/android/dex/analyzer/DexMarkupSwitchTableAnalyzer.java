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
package ghidra.file.formats.android.dex.analyzer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.file.formats.android.cdex.CDexConstants;
import ghidra.file.formats.android.dex.format.DexConstants;
import ghidra.file.formats.android.dex.format.PackedSwitchPayload;
import ghidra.file.formats.android.dex.format.SparseSwitchPayload;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class DexMarkupSwitchTableAnalyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		monitor.setMaximum(set == null ? program.getMemory().getSize() : set.getNumAddresses());
		monitor.setProgress(0);

		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		BinaryReader reader = new BinaryReader(provider, true);

		Listing listing = program.getListing();

		InstructionIterator instructionIterator = listing.getInstructions(set, true);
		while (instructionIterator.hasNext()) {
			Instruction instruction = instructionIterator.next();

			monitor.checkCanceled();
			monitor.incrementProgress(1);
			monitor.setMessage("DEX: Instruction markup ... " + instruction.getMinAddress());

			try {
				if (instruction.getMnemonicString().startsWith("packed_switch")) {
					if (instruction.getMnemonicReferences().length > 0) {// already done
						continue;
					}
					Scalar scalar = instruction.getScalar(1);
					Address address =
						instruction.getMinAddress().add(scalar.getUnsignedValue() * 2);
					if (program.getMemory().getShort(address) != PackedSwitchPayload.MAGIC) {
						log.appendMsg("invalid packed switch at " + address);
					}
					else {
						program.getReferenceManager()
								.addMemoryReference(instruction.getMinAddress(), address,
									RefType.DATA, SourceType.ANALYSIS, 1);

						reader.setPointerIndex(address.getOffset());
						PackedSwitchPayload payload = new PackedSwitchPayload(reader);
						DataType dataType = payload.toDataType();
						createData(program, address, dataType);

						processPacked(program, instruction, payload, monitor);
						//TODO setFallThrough( program, instruction );
					}
				}
				else if (instruction.getMnemonicString().startsWith("sparse_switch")) {
					if (instruction.getMnemonicReferences().length > 0) {// already done
						continue;
					}
					Scalar scalar = instruction.getScalar(1);
					Address address =
						instruction.getMinAddress().add(scalar.getUnsignedValue() * 2);

					if (program.getMemory().getShort(address) != SparseSwitchPayload.MAGIC) {
						log.appendMsg("invalid sparse switch at " + address);
					}
					else {
						program.getReferenceManager()
								.addMemoryReference(instruction.getMinAddress(), address,
									RefType.DATA, SourceType.ANALYSIS, 1);

						reader.setPointerIndex(address.getOffset());
						SparseSwitchPayload payload = new SparseSwitchPayload(reader);
						DataType dataType = payload.toDataType();
						createData(program, address, dataType);

						processSparse(program, instruction, payload, monitor);
						//TODO setFallThrough( program, instruction );
					}
				}
			}
			catch (MemoryAccessException e) {
				log.appendMsg("unable to process switch at " + instruction.getMinAddress());
			}
		}

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		return DexConstants.isDexFile(provider) || CDexConstants.isCDEX(program);
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.INSTRUCTION_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Android DEX/CDEX Switch Table Markup";
	}

	@Override
	public String getName() {
		return "Android DEX/CDEX Switch Table Markup";
	}

	@Override
	public AnalysisPriority getPriority() {
		return new AnalysisPriority(3);
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

//	private void setFallThrough( Program program, Instruction instruction ) {
//		Address fallThroughAddress = instruction.getMaxAddress( ).add( 1 );
//		instruction.setFallThrough( fallThroughAddress );
//		DisassembleCommand dCommand = new DisassembleCommand( fallThroughAddress, null, true );
//		dCommand.applyTo( program );
//	}

	private void processPacked(Program program, Instruction instruction,
			PackedSwitchPayload payload, TaskMonitor monitor) throws Exception {
		String namespaceName = "pswitch_" + instruction.getMinAddress();
		Namespace nameSpace = DexUtil.getOrCreateNameSpace(program, namespaceName);

		int key = payload.getFirstKey();
		for (int target : payload.getTargets()) {
			monitor.checkCanceled();

			String caseName = "case_0x" + Integer.toHexString(key);
			Address caseAddress = instruction.getMinAddress().add(target * 2);
			program.getSymbolTable()
					.createLabel(caseAddress, caseName, nameSpace, SourceType.ANALYSIS);
			program.getReferenceManager()
					.addMemoryReference(instruction.getMinAddress(), caseAddress,
						RefType.COMPUTED_JUMP, SourceType.ANALYSIS, CodeUnit.MNEMONIC);
			DisassembleCommand dCommand = new DisassembleCommand(caseAddress, null, true);
			dCommand.applyTo(program);
			++key;
		}
	}

	private void processSparse(Program program, Instruction instruction,
			SparseSwitchPayload payload, TaskMonitor monitor) throws Exception {
		String namespaceName = "sswitch_" + instruction.getMinAddress();
		Namespace nameSpace = DexUtil.getOrCreateNameSpace(program, namespaceName);

		for (int i = 0; i < payload.getSize(); ++i) {
			monitor.checkCanceled();

			String caseName = "case_0x" + Integer.toHexString(payload.getKeys()[i]);
			Address caseAddress = instruction.getMinAddress().add(payload.getTargets()[i] * 2);
			program.getSymbolTable()
					.createLabel(caseAddress, caseName, nameSpace, SourceType.ANALYSIS);
			program.getReferenceManager()
					.addMemoryReference(instruction.getMinAddress(), caseAddress,
						RefType.COMPUTED_JUMP, SourceType.ANALYSIS, CodeUnit.MNEMONIC);
			DisassembleCommand dCommand = new DisassembleCommand(caseAddress, null, true);
			dCommand.applyTo(program);
		}
	}
}
