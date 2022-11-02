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
package ghidra.file.formats.dump.mdmp;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class SystemMemoryInfoStream implements StructConverter {

	public final static String NAME = "MINIDUMP_SYSTEM_MEMORY_INFO";

	private short revision;
	private short flags;

	private String NAME0 = "MINIDUMP_SYSTEM_BASIC_INFORMATION";
	private String NAME1 = "MINIDUMP_SYSTEM_FILECACHE_INFORMATION";
	private String NAME2 = "MINIDUMP_SYSTEM_BASIC_PERFORMANCE_INFORMATION";
	private String NAME3 = "MINIDUMP_SYSTEM_PERFORMANCE_INFORMATION";

	// MINIDUMP_SYSTEM_BASIC_INFORMATION
	private int basicTimerResolution;
	private int basicPageSize;
	private int basicNumberOfPhysicalPages;
	private int basicLowestPhysicalPageNumber;
	private int basicHighestPhysicalPageNumber;
	private int basicAllocationGranularity;
	private long basicMinimumUserModeAddress;
	private long basicMaximumUserModeAddress;
	private long basicActiveProcessorsAffinityMask;
	private int basicNumberOfProcessors;

	// MINIDUMP_SYSTEM_FILECACHE_INFORMATION
	private long fcCurrentSize;
	private long fcPeakSize;
	private int fcPageFaultCount;
	private long fcMinimumWorkingSet;
	private long fcMaximumWorkingSet;
	private long fcCurrentSizeIncludingTransitionInPages;
	private long fcPeakSizeIncludingTransitionInPages;
	private int fcTransitionRePurposeCount;
	private int fcFlags;

	// MINIDUMP_SYSTEM_BASIC_PERFORMANCE_INFORMATION
	private long bpAvailablePages;
	private long bpCommittedPages;
	private long bpCommitLimit;
	private long bpPeakCommitment;

	// MINIDUMP_SYSTEM_PERFORMANCE_INFORMATION
	private long perfIdleProcessTime;
	private long perfIoReadTransferCount;
	private long perfIoWriteTransferCount;
	private long perfIoOtherTransferCount;
	private int perfIoReadOperationCount;
	private int perfIoWriteOperationCount;
	private int perfIoOtherOperationCount;
	private int perfAvailablePages;
	private int perfCommittedPages;
	private int perfCommitLimit;
	private int perfPeakCommitment;
	private int perfPageFaultCount;
	private int perfCopyOnWriteCount;
	private int perfTransitionCount;
	private int perfCacheTransitionCount;
	private int perfDemandZeroCount;
	private int perfPageReadCount;
	private int perfPageReadIoCount;
	private int perfCacheReadCount;
	private int perfCacheIoCount;
	private int perfDirtyPagesWriteCount;
	private int perfDirtyWriteIoCount;
	private int perfMappedPagesWriteCount;
	private int perfMappedWriteIoCount;
	private int perfPagedPoolPages;
	private int perfNonPagedPoolPages;
	private int perfPagedPoolAllocs;
	private int perfPagedPoolFrees;
	private int perfNonPagedPoolAllocs;
	private int perfNonPagedPoolFrees;
	private int perfFreeSystemPtes;
	private int perfResidentSystemCodePage;
	private int perfTotalSystemDriverPages;
	private int perfTotalSystemCodePages;
	private int perfNonPagedPoolLookasideHits;
	private int perfPagedPoolLookasideHits;
	private int perfAvailablePagedPoolPages;
	private int perfResidentSystemCachePage;
	private int perfResidentPagedPoolPage;
	private int perfResidentSystemDriverPage;
	private int perfCcFastReadNoWait;
	private int perfCcFastReadWait;
	private int perfCcFastReadResourceMiss;
	private int perfCcFastReadNotPossible;
	private int perfCcFastMdlReadNoWait;
	private int perfCcFastMdlReadWait;
	private int perfCcFastMdlReadResourceMiss;
	private int perfCcFastMdlReadNotPossible;
	private int perfCcMapDataNoWait;
	private int perfCcMapDataWait;
	private int perfCcMapDataNoWaitMiss;
	private int perfCcMapDataWaitMiss;
	private int perfCcPinMappedDataCount;
	private int perfCcPinReadNoWait;
	private int perfCcPinReadWait;
	private int perfCcPinReadNoWaitMiss;
	private int perfCcPinReadWaitMiss;
	private int perfCcCopyReadNoWait;
	private int perfCcCopyReadWait;
	private int perfCcCopyReadNoWaitMiss;
	private int perfCcCopyReadWaitMiss;
	private int perfCcMdlReadNoWait;
	private int perfCcMdlReadWait;
	private int perfCcMdlReadNoWaitMiss;
	private int perfCcMdlReadWaitMiss;
	private int perfCcReadAheadIos;
	private int perfCcLazyWriteIos;
	private int perfCcLazyWritePages;
	private int perfCcDataFlushes;
	private int perfCcDataPages;
	private int ContextSwitches;
	private int FirstLevelTbFills;
	private int SecondLevelTbFills;
	private int SystemCalls;
	private long perfCcTotalDirtyPages;
	private long perfCcDirtyPageThreshold;
	private long perfResidentAvailablePages;
	private long perfSharedCommittedPages;

	private DumpFileReader reader;
	private long index;

	SystemMemoryInfoStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		revision = reader.readNextShort();
		flags = reader.readNextShort();

		// MINIDUMP_SYSTEM_BASIC_INFORMATION
		basicTimerResolution = reader.readNextInt();
		basicPageSize = reader.readNextInt();
		basicNumberOfPhysicalPages = reader.readNextInt();
		basicLowestPhysicalPageNumber = reader.readNextInt();
		basicHighestPhysicalPageNumber = reader.readNextInt();
		basicAllocationGranularity = reader.readNextInt();
		basicMinimumUserModeAddress = reader.readNextLong();
		basicMaximumUserModeAddress = reader.readNextLong();
		basicActiveProcessorsAffinityMask = reader.readNextLong();
		basicNumberOfProcessors = reader.readNextInt();

		// MINIDUMP_SYSTEM_FILECACHE_INFORMATION
		fcCurrentSize = reader.readNextLong();
		fcPeakSize = reader.readNextLong();
		fcPageFaultCount = reader.readNextInt();
		fcMinimumWorkingSet = reader.readNextLong();
		fcMaximumWorkingSet = reader.readNextLong();
		fcCurrentSizeIncludingTransitionInPages = reader.readNextLong();
		fcPeakSizeIncludingTransitionInPages = reader.readNextLong();
		fcTransitionRePurposeCount = reader.readNextInt();
		fcFlags = reader.readNextInt();

		// MINIDUMP_SYSTEM_BASIC_PERFORMANCE_INFORMATION
		bpAvailablePages = reader.readNextLong();
		bpCommittedPages = reader.readNextLong();
		bpCommitLimit = reader.readNextLong();
		bpPeakCommitment = reader.readNextLong();

		// MINIDUMP_SYSTEM_PERFORMANCE_INFORMATION
		perfIdleProcessTime = reader.readNextLong();
		perfIoReadTransferCount = reader.readNextLong();
		perfIoWriteTransferCount = reader.readNextLong();
		perfIoOtherTransferCount = reader.readNextLong();
		perfIoReadOperationCount = reader.readNextInt();
		perfIoWriteOperationCount = reader.readNextInt();
		perfIoOtherOperationCount = reader.readNextInt();
		perfAvailablePages = reader.readNextInt();
		perfCommittedPages = reader.readNextInt();
		perfCommitLimit = reader.readNextInt();
		perfPeakCommitment = reader.readNextInt();
		perfPageFaultCount = reader.readNextInt();
		perfCopyOnWriteCount = reader.readNextInt();
		perfTransitionCount = reader.readNextInt();
		perfCacheTransitionCount = reader.readNextInt();
		perfDemandZeroCount = reader.readNextInt();
		perfPageReadCount = reader.readNextInt();
		perfPageReadIoCount = reader.readNextInt();
		perfCacheReadCount = reader.readNextInt();
		perfCacheIoCount = reader.readNextInt();
		perfDirtyPagesWriteCount = reader.readNextInt();
		perfDirtyWriteIoCount = reader.readNextInt();
		perfMappedPagesWriteCount = reader.readNextInt();
		perfMappedWriteIoCount = reader.readNextInt();
		perfPagedPoolPages = reader.readNextInt();
		perfNonPagedPoolPages = reader.readNextInt();
		perfPagedPoolAllocs = reader.readNextInt();
		perfPagedPoolFrees = reader.readNextInt();
		perfNonPagedPoolAllocs = reader.readNextInt();
		perfNonPagedPoolFrees = reader.readNextInt();
		perfFreeSystemPtes = reader.readNextInt();
		perfResidentSystemCodePage = reader.readNextInt();
		perfTotalSystemDriverPages = reader.readNextInt();
		perfTotalSystemCodePages = reader.readNextInt();
		perfNonPagedPoolLookasideHits = reader.readNextInt();
		perfPagedPoolLookasideHits = reader.readNextInt();
		perfAvailablePagedPoolPages = reader.readNextInt();
		perfResidentSystemCachePage = reader.readNextInt();
		perfResidentPagedPoolPage = reader.readNextInt();
		perfResidentSystemDriverPage = reader.readNextInt();
		perfCcFastReadNoWait = reader.readNextInt();
		perfCcFastReadWait = reader.readNextInt();
		perfCcFastReadResourceMiss = reader.readNextInt();
		perfCcFastReadNotPossible = reader.readNextInt();
		perfCcFastMdlReadNoWait = reader.readNextInt();
		perfCcFastMdlReadWait = reader.readNextInt();
		perfCcFastMdlReadResourceMiss = reader.readNextInt();
		perfCcFastMdlReadNotPossible = reader.readNextInt();
		perfCcMapDataNoWait = reader.readNextInt();
		perfCcMapDataWait = reader.readNextInt();
		perfCcMapDataNoWaitMiss = reader.readNextInt();
		perfCcMapDataWaitMiss = reader.readNextInt();
		perfCcPinMappedDataCount = reader.readNextInt();
		perfCcPinReadNoWait = reader.readNextInt();
		perfCcPinReadWait = reader.readNextInt();
		perfCcPinReadNoWaitMiss = reader.readNextInt();
		perfCcPinReadWaitMiss = reader.readNextInt();
		perfCcCopyReadNoWait = reader.readNextInt();
		perfCcCopyReadWait = reader.readNextInt();
		perfCcCopyReadNoWaitMiss = reader.readNextInt();
		perfCcCopyReadWaitMiss = reader.readNextInt();
		perfCcMdlReadNoWait = reader.readNextInt();
		perfCcMdlReadWait = reader.readNextInt();
		perfCcMdlReadNoWaitMiss = reader.readNextInt();
		perfCcMdlReadWaitMiss = reader.readNextInt();
		perfCcReadAheadIos = reader.readNextInt();
		perfCcLazyWriteIos = reader.readNextInt();
		perfCcLazyWritePages = reader.readNextInt();
		perfCcDataFlushes = reader.readNextInt();
		perfCcDataPages = reader.readNextInt();
		ContextSwitches = reader.readNextInt();
		FirstLevelTbFills = reader.readNextInt();
		SecondLevelTbFills = reader.readNextInt();
		SystemCalls = reader.readNextInt();
		perfCcTotalDirtyPages = reader.readNextLong();
		perfCcDirtyPageThreshold = reader.readNextLong();
		perfResidentAvailablePages = reader.readNextLong();
		perfSharedCommittedPages = reader.readNextLong();

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(WORD, 2, "Revision", null);
		struct.add(WORD, 2, "Flags", null);

		StructureDataType s0 = new StructureDataType(NAME0, 0);
		StructureDataType s1 = new StructureDataType(NAME1, 0);
		StructureDataType s2 = new StructureDataType(NAME2, 0);
		StructureDataType s3 = new StructureDataType(NAME3, 0);

		s0.add(DWORD, 4, "TimerResolution", null);
		s0.add(DWORD, 4, "PageSize", null);
		s0.add(DWORD, 4, "NumberOfPhysicalPages", null);
		s0.add(DWORD, 4, "LowestPhysicalPageNumber", null);
		s0.add(DWORD, 4, "HighestPhysicalPageNumber", null);
		s0.add(DWORD, 4, "AllocationGranularity", null);
		s0.add(QWORD, 8, "MinimumUserModeAddress", null);
		s0.add(QWORD, 8, "MaximumUserModeAddress", null);
		s0.add(QWORD, 8, "ActiveProcessorsAffinityMask", null);
		s0.add(DWORD, 4, "NumberOfProcessors", null);

		struct.add(s0, s0.getLength(), NAME0, null);

		s1.add(QWORD, 8, "CurrentSize", null);
		s1.add(QWORD, 8, "PeakSize", null);
		s1.add(DWORD, 4, "PageFaultCount", null);
		s1.add(QWORD, 8, "MinimumWorkingSet", null);
		s1.add(QWORD, 8, "MaximumWorkingSet", null);
		s1.add(QWORD, 8, "CurrentSizeIncludingTransitionInPages", null);
		s1.add(QWORD, 8, "PeakSizeIncludingTransitionInPages", null);
		s1.add(DWORD, 4, "TransitionRePurposeCount", null);
		s1.add(DWORD, 4, "Flags", null);

		struct.add(s1, s1.getLength(), NAME1, null);

		s2.add(QWORD, 8, "AvailablePages", null);
		s2.add(QWORD, 8, "CommittedPages", null);
		s2.add(QWORD, 8, "CommitLimit", null);
		s2.add(QWORD, 8, "PeakCommitment", null);

		struct.add(s2, s2.getLength(), NAME2, null);

		s3.add(QWORD, 8, "IdleProcessTime", null);
		s3.add(QWORD, 8, "IoReadTransferCount", null);
		s3.add(QWORD, 8, "IoWriteTransferCount", null);
		s3.add(QWORD, 8, "IoOtherTransferCount", null);
		s3.add(DWORD, 4, "IoReadOperationCount", null);
		s3.add(DWORD, 4, "IoWriteOperationCount", null);
		s3.add(DWORD, 4, "IoOtherOperationCount", null);
		s3.add(DWORD, 4, "AvailablePages", null);
		s3.add(DWORD, 4, "CommittedPages", null);
		s3.add(DWORD, 4, "CommitLimit", null);
		s3.add(DWORD, 4, "PeakCommitment", null);
		s3.add(DWORD, 4, "PageFaultCount", null);
		s3.add(DWORD, 4, "CopyOnWriteCount", null);
		s3.add(DWORD, 4, "TransitionCount", null);
		s3.add(DWORD, 4, "CacheTransitionCount", null);
		s3.add(DWORD, 4, "DemandZeroCount", null);
		s3.add(DWORD, 4, "PageReadCount", null);
		s3.add(DWORD, 4, "PageReadIoCount", null);
		s3.add(DWORD, 4, "CacheReadCount", null);
		s3.add(DWORD, 4, "CacheIoCount", null);
		s3.add(DWORD, 4, "DirtyPagesWriteCount", null);
		s3.add(DWORD, 4, "DirtyWriteIoCount", null);
		s3.add(DWORD, 4, "MappedPagesWriteCount", null);
		s3.add(DWORD, 4, "MappedWriteIoCount", null);
		s3.add(DWORD, 4, "PagedPoolPages", null);
		s3.add(DWORD, 4, "NonPagedPoolPages", null);
		s3.add(DWORD, 4, "PagedPoolAllocs", null);
		s3.add(DWORD, 4, "PagedPoolFrees", null);
		s3.add(DWORD, 4, "NonPagedPoolAllocs", null);
		s3.add(DWORD, 4, "NonPagedPoolFrees", null);
		s3.add(DWORD, 4, "FreeSystemPtes", null);
		s3.add(DWORD, 4, "ResidentSystemCodePage", null);
		s3.add(DWORD, 4, "TotalSystemDriverPages", null);
		s3.add(DWORD, 4, "TotalSystemCodePages", null);
		s3.add(DWORD, 4, "NonPagedPoolLookasideHits", null);
		s3.add(DWORD, 4, "PagedPoolLookasideHits", null);
		s3.add(DWORD, 4, "AvailablePagedPoolPages", null);
		s3.add(DWORD, 4, "ResidentSystemCachePage", null);
		s3.add(DWORD, 4, "ResidentPagedPoolPage", null);
		s3.add(DWORD, 4, "ResidentSystemDriverPage", null);
		s3.add(DWORD, 4, "CcFastReadNoWait", null);
		s3.add(DWORD, 4, "CcFastReadWait", null);
		s3.add(DWORD, 4, "CcFastReadResourceMiss", null);
		s3.add(DWORD, 4, "CcFastReadNotPossible", null);
		s3.add(DWORD, 4, "CcFastMdlReadNoWait", null);
		s3.add(DWORD, 4, "CcFastMdlReadWait", null);
		s3.add(DWORD, 4, "CcFastMdlReadResourceMiss", null);
		s3.add(DWORD, 4, "CcFastMdlReadNotPossible", null);
		s3.add(DWORD, 4, "CcMapDataNoWait", null);
		s3.add(DWORD, 4, "CcMapDataWait", null);
		s3.add(DWORD, 4, "CcMapDataNoWaitMiss", null);
		s3.add(DWORD, 4, "CcMapDataWaitMiss", null);
		s3.add(DWORD, 4, "CcPinMappedDataCount", null);
		s3.add(DWORD, 4, "CcPinReadNoWait", null);
		s3.add(DWORD, 4, "CcPinReadWait", null);
		s3.add(DWORD, 4, "CcPinReadNoWaitMiss", null);
		s3.add(DWORD, 4, "CcPinReadWaitMiss", null);
		s3.add(DWORD, 4, "CcCopyReadNoWait", null);
		s3.add(DWORD, 4, "CcCopyReadWait", null);
		s3.add(DWORD, 4, "CcCopyReadNoWaitMiss", null);
		s3.add(DWORD, 4, "CcCopyReadWaitMiss", null);
		s3.add(DWORD, 4, "CcMdlReadNoWait", null);
		s3.add(DWORD, 4, "CcMdlReadWait", null);
		s3.add(DWORD, 4, "CcMdlReadNoWaitMiss", null);
		s3.add(DWORD, 4, "CcMdlReadWaitMiss", null);
		s3.add(DWORD, 4, "CcReadAheadIos", null);
		s3.add(DWORD, 4, "CcLazyWriteIos", null);
		s3.add(DWORD, 4, "CcLazyWritePages", null);
		s3.add(DWORD, 4, "CcDataFlushes", null);
		s3.add(DWORD, 4, "CcDataPages", null);
		s3.add(DWORD, 4, "ContextSwitches", null);
		s3.add(DWORD, 4, "FirstLevelTbFills", null);
		s3.add(DWORD, 4, "SecondLevelTbFills", null);
		s3.add(DWORD, 4, "SystemCalls", null);

		s3.add(QWORD, 8, "CcTotalDirtyPages", null);
		s3.add(QWORD, 8, "CcDirtyPageThreshold", null);

		s3.add(QWORD, 8, "ResidentAvailablePages", null);
		s3.add(QWORD, 8, "SharedCommittedPages", null);

		struct.add(s3, s3.getLength(), NAME3, null);

		return struct;
	}

}
