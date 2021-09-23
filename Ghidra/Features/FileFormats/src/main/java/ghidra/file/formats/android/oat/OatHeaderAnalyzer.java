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
package ghidra.file.formats.android.oat;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class OatHeaderAnalyzer extends FileFormatAnalyzer {

	@Override
	public String getName() {
		return "Android OAT Header Format";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Analyzes the Android OAT sections (oatdata and oatexec) in this program.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		return OatConstants.isOAT(program);
	}

	@Override
	public boolean isPrototype() {
		return true;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		clearIfNeeded(program, monitor, log);

		Symbol oatDataSymbol = OatUtilities.getOatDataSymbol(program);
		Address address = oatDataSymbol.getAddress();

		BinaryReader reader = OatUtilities.getBinaryReader(program);
		if (reader == null) {
			return false;
		}

		OatHeader oatHeader = null;
		try {
			oatHeader = OatHeaderFactory.newOatHeader(reader);

			OatHeaderFactory.parseOatHeader(oatHeader, program, reader, monitor, log);
		}
		catch (UnsupportedOatVersionException e) {
			log.appendMsg(e.getMessage());
			return false;
		}

		try {
			DataType headerDataType = oatHeader.toDataType();
			Data headerData = createData(program, address, headerDataType);
			address = address.add(headerDataType.getLength());

			markupClassOffsets(program, oatDataSymbol, oatHeader, headerData, monitor, log);

			monitor.setMessage("Applying OAT DEX headers...");
			monitor.initialize(oatHeader.getOatDexFileList().size());

			for (int i = 0; i < oatHeader.getOatDexFileList().size(); ++i) {
				monitor.checkCanceled();
				monitor.setMessage("Applying OAT DEX class offsets [ Pass " + i + " of " +
					oatHeader.getOatDexFileList().size() + " ]...");
				monitor.incrementProgress(1);

				OatDexFile oatDexFileHeader = oatHeader.getOatDexFileList().get(i);

				oatDexFileHeader.markup(oatHeader, program, monitor, log);

				applyDexHeader(program, oatDexFileHeader, oatDataSymbol, i);
			}

			markupOatPatches(program, oatHeader, monitor, log);
		}
		catch (Exception e) {
			throw e;
		}
		finally {
			oatHeader = null;
		}
		return true;
	}

	/**
	 * Ghidra sometimes applies undefined1[x] at "oatdata" and "oatexec".
	 * This method checks for these arrays and clears if they exist.
	 */
	private void clearIfNeeded(Program program, TaskMonitor monitor, MessageLog log) {
		Symbol oatDataSymbol = OatUtilities.getOatDataSymbol(program);
		Data oatDataSymbolData = program.getListing().getDefinedDataAt(oatDataSymbol.getAddress());
		if (oatDataSymbolData != null && oatDataSymbolData.isArray()) {
			Array array = (Array) oatDataSymbolData.getDataType();
			if (array.getDataType().isEquivalent(new Undefined1DataType())) {
				program.getListing()
						.clearCodeUnits(oatDataSymbolData.getMinAddress(),
							oatDataSymbolData.getMaxAddress(), false);
			}
		}
		Symbol oatExecSymbol = OatUtilities.getOatExecSymbol(program);
		if (oatExecSymbol != null) {
			Data oatExecSymbolData =
				program.getListing().getDefinedDataAt(oatExecSymbol.getAddress());
			if (oatExecSymbolData != null && oatExecSymbolData.isArray()) {
				Array array = (Array) oatExecSymbolData.getBaseDataType();
				if (array.getDataType().isEquivalent(new Undefined1DataType())) {
					program.getListing()
							.clearCodeUnits(oatExecSymbolData.getMinAddress(),
								oatExecSymbolData.getMaxAddress(), false);
				}
			}
		}
		Symbol oatLastWordSymbol = OatUtilities.getOatLastWordSymbol(program);
		if (oatLastWordSymbol != null) {
			Data oatLastWordSymbolData =
				program.getListing().getDefinedDataAt(oatLastWordSymbol.getAddress());
			if (oatLastWordSymbolData != null) {
				program.getListing()
						.clearCodeUnits(oatLastWordSymbolData.getMinAddress(),
							oatLastWordSymbolData.getMaxAddress(), false);
			}
		}
	}

	/**
	 * Annotates the listing for the ".oat_patches" section(s).  
	 * The format of the section changes based on the OAT version.
	 */
	private void markupOatPatches(Program program, OatHeader oatHeader, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Annotating OAT Patches...");
		Memory memory = program.getMemory();

		if (oatHeader.getVersion().equals(OatConstants.VERSION_LOLLIPOP_MR1_FI_RELEASE)) {
			MemoryBlock oatBlock = memory.getBlock(OatConstants.DOT_OAT_PATCHES_SECTION_NAME);
			MemoryBlock destinationBlock = findOatPatchesDestinationBlock(program, oatBlock);
			if (oatBlock == null || destinationBlock == null) {
				log.appendMsg("Could not locate OAT patches source / destination block.");
				return;
			}
			DataType dataType = new DWordDataType();
			monitor.setProgress(0);
			long numberOfElements = oatBlock.getSize() / dataType.getLength();
			monitor.setMaximum(numberOfElements);
			for (int i = 0; i < numberOfElements; ++i) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				try {
					Address address = oatBlock.getStart().add(i * dataType.getLength());
					Data data = createData(program, address, dataType);
					Scalar scalar = data.getScalar(0);
					Address toAddr = destinationBlock.getStart().add(scalar.getUnsignedValue());
					program.getListing().setComment(address, CodeUnit.EOL_COMMENT, "->" + toAddr);
				}
				catch (Exception e) {
					log.appendException(e);
					return;
				}
			}
		}
		else if (oatHeader.getVersion().equals(OatConstants.VERSION_MARSHMALLOW_RELEASE)) {
			//TODO
		}
		else if (oatHeader.getVersion().equals(OatConstants.VERSION_NOUGAT_MR1_RELEASE)) {
			//TODO
		}
		else if (oatHeader.getVersion().equals(OatConstants.VERSION_OREO_RELEASE)) {
			//TODO
		}
		else if (oatHeader.getVersion().equals(OatConstants.VERSION_OREO_M2_RELEASE)) {
			//TODO
		}
	}

	private MemoryBlock findOatPatchesDestinationBlock(Program program,
			MemoryBlock oatPatchesBlock) {
		int pos = oatPatchesBlock.getName().indexOf(OatConstants.DOT_OAT_PATCHES_SECTION_NAME);
		if (pos == 0) {//the block's full name is ".oat_patches"
			return program.getMemory().getBlock(ElfSectionHeaderConstants.dot_text);
		}
		//the block has a prefix, that is the destination name
		String destinationBlockName = oatPatchesBlock.getName().substring(0, pos);
		return program.getMemory().getBlock(destinationBlockName);
	}

	private void applyDexHeader(Program program, OatDexFile oatDexFileHeader, Symbol oatDataSymbol,
			int index) throws Exception {

		Address address = oatDataSymbol.getAddress().add(oatDexFileHeader.getDexFileOffset());

		DexHeader dexHeader = oatDexFileHeader.getDexHeader();

		if (dexHeader == null) {
			return;
		}

		if (oatDexFileHeader.isDexHeaderExternal()) {
			return;
		}

		DataType dexHeaderDataType = dexHeader.toDataType();
		try {
			dexHeaderDataType.setName(dexHeaderDataType.getName() + "_" + index);
		}
		catch (Exception e) {
			//ignore
		}

		createData(program, address, dexHeaderDataType);

		address = address.add(dexHeaderDataType.getLength());

		int dexRemainder = dexHeader.getFileSize() - dexHeaderDataType.getLength();
		if (dexRemainder > 0) {
			DataType paddingDataType = new ArrayDataType(StructConverter.BYTE, dexRemainder,
				StructConverter.BYTE.getLength());
			createData(program, address, paddingDataType);
		}
	}

	private void markupClassOffsets(Program program, Symbol oatDataSymbol, OatHeader oatHeader,
			Data headerData, TaskMonitor monitor, MessageLog log) throws CancelledException {

		SymbolTable symbolTable = program.getSymbolTable();
		ReferenceManager referenceManager = program.getReferenceManager();
		EquateTable equateTable = program.getEquateTable();

		for (int i = 0; i < headerData.getNumComponents(); ++i) {
			monitor.checkCanceled();
			if (!headerData.getComponent(i).getFieldName().equals("executable_offset_") &&
				headerData.getComponent(i).getFieldName().endsWith("_offset_")) {
				Scalar scalar = headerData.getComponent(i).getScalar(0);
				if (scalar.getUnsignedValue() > 0) {
					Address toAddr = oatDataSymbol.getAddress().add(scalar.getUnsignedValue());
					toAddr = OatUtilities.adjustForThumbAsNeeded(oatHeader, program, toAddr, log);

					referenceManager.addMemoryReference(headerData.getComponent(i).getMinAddress(),
						toAddr, RefType.DATA, SourceType.ANALYSIS, 0);
					try {
						symbolTable.createLabel(toAddr, headerData.getComponent(i).getFieldName(),
							SourceType.ANALYSIS);

						disassembleAsNeeded(program, toAddr);
					}
					catch (Exception e) {
						//ignore...
					}
				}
			}
			else if (headerData.getComponent(i)
					.getFieldName()
					.equals(OatInstructionSet.DISPLAY_NAME)) {
				try {
					Scalar scalar = headerData.getComponent(i).getScalar(0);
					OatInstructionSet instructionSet =
						OatInstructionSet.valueOf((int) scalar.getUnsignedValue());
					Equate equate =
						equateTable.createEquate(instructionSet.name(), scalar.getUnsignedValue());
					equate.addReference(headerData.getComponent(i).getMinAddress(), 0);
				}
				catch (Exception e) {
					//ignore...
				}
			}
		}
	}

	/**
	 * Check to see if points to instructions and not undefined, if so then disassemble.
	 */
	private void disassembleAsNeeded(Program program, Address toAddr) {
		if (program.getMemory().contains(toAddr) &&
			program.getMemory().getBlock(toAddr).isExecute()) {
			if (program.getListing().isUndefined(toAddr, toAddr)) {
				DisassembleCommand cmd = new DisassembleCommand(toAddr, null, false);
				cmd.applyTo(program);
			}
		}
	}

}
