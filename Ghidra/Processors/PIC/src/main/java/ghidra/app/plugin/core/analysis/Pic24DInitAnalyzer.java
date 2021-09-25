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

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.GhidraDataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Pic24DInitAnalyzer extends AbstractAnalyzer {
	
	private static final int DST_ORDINAL = 0;
	private static final int LEN_ORDINAL = 1;
	private static final int FORMAT_ORDINAL = 2;
	private static final int PAGE_ORDINAL = 3;

	public Pic24DInitAnalyzer() {
		super("DInit Analyzer", "Processes .dinit Data Initialization Section", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
		setDefaultEnablement(true);
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		String processorName = program.getLanguage().getProcessor().toString();
		boolean isSupportedProcessor =
			processorName.contentEquals("PIC-24") || processorName.startsWith("dsPIC3");
		if (!isSupportedProcessor) {
			return false;
		}
		if (!ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
			return false;
		}
		return program.getMemory().getBlock(".dinit") != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		Listing listing = program.getListing();
		ReferenceManager referenceManager = program.getReferenceManager();
		
		MemoryBlock dinitBlock = program.getMemory().getBlock(".dinit");
		if (listing.getDefinedDataContaining(dinitBlock.getStart()) != null) {
			Msg.info(this, "Skipping .dinit processing due to existing data at " + dinitBlock.getStart());
			return true;
		}
		
		MemoryBufferImpl memBuffer = new MemoryBufferImpl(program.getMemory(), dinitBlock.getStart());
		long available = dinitBlock.getSize();
		
		Structure dataRecordType = new StructureDataType("data_record", 0, program.getDataTypeManager());
		dataRecordType.setPackingEnabled(true);
		dataRecordType.add(PointerDataType.dataType, "dst", null);
		// NOTE: long is used instead of int to ensure that 4-bytes within ROM are consumed
		dataRecordType.add(LongDataType.dataType, "len", null);
		try {
			dataRecordType.addBitField(LongDataType.dataType, 7, "format", null); // Valid formats: 0, 1, 2
			dataRecordType.addBitField(LongDataType.dataType, 9, "page", null); // TODO: factor into dst ram reference
		} catch (InvalidDataTypeException e) {
			throw new AssertException(e);
		}
		dataRecordType.add(new ArrayDataType(ByteDataType.dataType, 0, -1), "data", null);
		
		dataRecordType = (Structure) program.getDataTypeManager().resolve(dataRecordType, null);
		
		GhidraDataConverter converter = GhidraDataConverter.getInstance(false);
		
		AddressSpace dataSpace = program.getLanguage().getDefaultDataSpace();
		
		try {
			Address addr = dinitBlock.getStart();
			int offset = 0;
			while (offset < available) {
				short dst = converter.getShort(memBuffer, offset);
				if (dst == 0) {
					break;
				}
				Data dataRecord = listing.createData(addr, dataRecordType);
				
				Scalar len = (Scalar) dataRecord.getComponent(LEN_ORDINAL).getValue();
				Scalar format = (Scalar) dataRecord.getComponent(FORMAT_ORDINAL).getValue();
				Scalar page = (Scalar) dataRecord.getComponent(PAGE_ORDINAL).getValue();
				
				// replace dst reference
				Reference ref = referenceManager.getPrimaryReferenceFrom(addr, 0);
				if (ref != null) {
					referenceManager.delete(ref); // remove bad ref into ROM space
				}
				// TODO: use page
				Address dstAddr = dataSpace.getAddress(dst & 0x0ffff);
				referenceManager.addMemoryReference(addr, dstAddr, RefType.DATA, SourceType.ANALYSIS, 0);
				
				offset += dataRecordType.getLength();
				addr = addr.add(dataRecord.getLength());
				
				Data arrayData = null;
				long fmt = format.getValue();
				if (fmt != 0) {
					int flexArrayLen = 0;
					if (fmt == 1) { // 2-bytes consumed per 4-byte ROM location
						flexArrayLen = (int)(4 * ((len.getValue() + 1) / 2));
					}
					else if (fmt == 2) { // 3-bytes consumed per 4-byte ROM location
						flexArrayLen = (int)(4 * ((len.getValue() + 2) / 3));
					}
					else {
						Msg.error(this, "Invalid .dinit format value at " + dataRecord.getComponent(FORMAT_ORDINAL).getAddress());
						break;
					}
					
					// bounds check
					if (flexArrayLen < 0 || (offset + flexArrayLen) > available) {
						Msg.error(this, "Invalid .dinit len value at " + dataRecord.getComponent(LEN_ORDINAL).getAddress());
						break;
					}
					
					Array flexArray = new ArrayDataType(ByteDataType.dataType, flexArrayLen, 1);
					arrayData = listing.createData(addr, flexArray);

					offset += flexArrayLen;
					addr = addr.add(flexArrayLen);
				}
				
				// NOTE: ELF Loader already loads initialized data intended for ROM into mapped RAM regions
				// TODO: determine if it is necessary to perform actual initialization
				// initializeData(program, dstAddr, arrayData, fmt, len);
				
			}
		} catch (MemoryAccessException | CodeUnitInsertionException e) {
			Msg.error(this, "Failed during .dinit processing: " + e.getMessage());
		}
		
		return true;
	}

}
