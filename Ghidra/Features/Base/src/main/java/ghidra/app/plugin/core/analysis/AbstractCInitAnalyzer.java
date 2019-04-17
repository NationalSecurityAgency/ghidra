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
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractCInitAnalyzer extends AbstractAnalyzer {

	private static final String DESCRIPTION =
		"Initializes the .bss uninitilized memory using data from the .cinit section.";

	private String[] supportProcessors;

	private static final String CINIT = ".cinit";

	public AbstractCInitAnalyzer(String analyzerName, String... supportProcessors) {
		super(analyzerName, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		this.supportProcessors = supportProcessors;
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before().before());
	}

	private boolean isSupportedProcessor(Processor processor) {
		String processorName = processor.toString();
		for (String pname : supportProcessors) {
			if (processorName.equals(pname)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean canAnalyze(Program p) {
		if (!isSupportedProcessor(p.getLanguage().getProcessor())) {
			return false;
		}
		Memory mem = p.getMemory();
		MemoryBlock cinitBlock = mem.getBlock(CINIT);
		if (cinitBlock == null || !cinitBlock.isInitialized()) {
			return false;
		}
		return true;
	}

	public static class CInitRecord {

		private final Address cinitRecordAddr;
		private final Address sourceDataAddr;
		private final Address targetAddr;
		private final int dataLength;
		private final Address nextRecordAddr;

		/**
		 * Constructor
		 * @param cinitRecordAddr start of record address
		 * @param sourceDataAddr address within .cinit section where initialization
		 * data will be copied from
		 * @param targetAddr address within .bss section where initialization
		 * data will be copied to.  A null value will cause this record
		 * to be skipped.
		 * @param dataLength number of bytes contained within initialization data
		 * @param nextRecordAddr address of next .cinit record
		 */
		public CInitRecord(Address cinitRecordAddr, Address sourceDataAddr, Address targetAddr,
				int dataLength, Address nextRecordAddr) {
			this.cinitRecordAddr = cinitRecordAddr;
			this.sourceDataAddr = sourceDataAddr;
			this.targetAddr = targetAddr;
			this.dataLength = dataLength;
			this.nextRecordAddr = nextRecordAddr;
		}

		/**
		 * @return start of record address
		 */
		public Address getStartOfRecord() {
			return cinitRecordAddr;
		}

		/**
		 * @return true if record is terminal and contains no initialization
		 * data
		 */
		public boolean isTerminalRecord() {
			return getDataLength() == 0;
		}

		/**
		 * @return address within .bss section where initialization
		 * data will be copied to.  A null value will cause this record
		 * to be skipped.
		 */
		public Address getTargetAddress() {
			return targetAddr;
		}

		/**
		 * @return address within .cinit section where initialization
		 * data will be copied from
		 */
		public Address getSourceDataAddress() {
			return sourceDataAddr;
		}

		/**
		 * @return number of bytes contained within initialization data
		 */
		public int getDataLength() {
			return dataLength;
		}

		/**
		 * @return address of next .cinit record
		 */
		public Address getNextRecordAddress() {
			return nextRecordAddr;
		}
	}

	/**
	 * Get .cinint record and apply record data structure to program
	 * @param program
	 * @param cinitRecordAddr address of a .cinit record
	 * @return record object
	 */
	protected abstract CInitRecord getCinitRecord(Program program, Address cinitRecordAddr)
			throws CodeUnitInsertionException, AddressOverflowException;

	public synchronized boolean added(Program p, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {

		Memory mem = p.getMemory();
		MemoryBlock cinitBlock = mem.getBlock(CINIT);
		if (cinitBlock == null || !set.contains(cinitBlock.getStart())) {
			return true;
		}

		BookmarkManager bookmarkManager = p.getBookmarkManager();

		Address addr = cinitBlock.getStart();

		MemoryBlock block = null;
		try {
			while (addr.compareTo(cinitBlock.getEnd()) < 0) {

				CInitRecord initRec = getCinitRecord(p, addr);
				if (initRec.isTerminalRecord()) {
					break;
				}

				addr = initRec.getNextRecordAddress();

				Address dataAddr = initRec.getTargetAddress();
				if (dataAddr == null) {
					continue;
				}

				Address initDataAddr = initRec.getSourceDataAddress();
				int byteLen = initRec.getDataLength();

				block = mem.getBlock(dataAddr);
				if (block == null) {
					Msg.error(this, "Failed to initialize data at " + dataAddr +
						" - no memory defined");
					continue;
				}

				if (!block.isInitialized()) {
					mem.convertToInitialized(block, (byte) 0);
					block.setWrite(true);
				}

				// Read .cinit bytes and copy to intended target address
				byte[] bytes = new byte[byteLen];
				if (byteLen != cinitBlock.getBytes(initDataAddr, bytes)) {
					// we created data - should not have problem reading bytes
					throw new MemoryAccessException("unexpected end of .cinit block");
				}

				Msg.debug(this, byteLen + "-bytes at " + dataAddr +
					" initialized from .cinit data at " + initDataAddr);

				block.putBytes(dataAddr, bytes);

				bookmarkManager.setBookmark(dataAddr, BookmarkType.ANALYSIS, "Data Initilized",
					byteLen + "-bytes initialized from .cinit data at " + initDataAddr);

			}
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "Error occured during block initialization: " + e.getMessage());
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(this, "Failed to create .cinit data structure: " + e.getMessage());
		}
		catch (AddressOverflowException e) {
			Msg.error(this, "Unexpected end of .cinit block");
		}
		catch (LockException e) {
			Msg.showError(this, null, getName() + " Failed", getName() +
				" requires exclusive check-out to perform " + block.getName() +
				" memory block initialization");
			return false;
		}
		catch (NotFoundException e) {
			throw new AssertException(e); // Unexpected
		}

		return true;
	}
}
