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
package ghidra.file.formats.dump.pagedump;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;

public class KdDebuggerData implements StructConverter {

	public final static String NAME = "_KD_DEBUGGER_DATA";

	// NB:  Harvested from wdbgexts.h

	// DBGKD_DEBUG_DATA_HEADER64 Header;

	//
	// Link to other blocks
	//

	private long List_Flink;
	private long List_Blink;

	//
	// This is a unique tag to identify the owner of the block.
	// If your component only uses one pool tag, use it for this, too.
	//

	private int OwnerTag;

	//
	// This must be initialized to the size of the data block,
	// including this structure.
	//

	private int Size;

	//
	// Base address of kernel image
	//

	private long KernBase;

	//
	// DbgBreakPointWithStatus is a function which takes an argument
	// and hits a breakpoint.  This field contains the address of the
	// breakpoint instruction.  When the debugger sees a breakpoint
	// at this address, it may retrieve the argument from the first
	// argument register, or on x86 the eax register.
	//

	private long BreakpointWithStatus;       // address of breakpoint

	//
	// Address of the saved context record during a bugcheck
	//
	// N.B. This is an automatic in KeBugcheckEx's frame, and
	// is only valid after a bugcheck.
	//

	private long SavedContext;

	//
	// help for walking stacks with user callbacks:
	//

	//
	// The address of the thread structure is provided in the
	// WAIT_STATE_CHANGE packet.  This is the offset from the base of
	// the thread structure to the pointer to the kernel stack frame
	// for the currently active usermode callback.
	//

	private short ThCallbackStack;            // offset in thread data

	//
	// these values are offsets into that frame:
	//

	private short NextCallback;               // saved pointer to next callback frame
	private short FramePointer;               // saved frame pointer

	//
	// pad to a quad boundary
	//
	/*
	private short  PaeEnabled:1;
	private short  KiBugCheckRecoveryActive:1; // Windows 10 Manganese Addition
	private short  PagingLevels:4;
	*/
	private short Flags;

	//
	// Address of the kernel callout routine.
	//

	private long KiCallUserMode;             // kernel routine

	//
	// Address of the usermode entry point for callbacks.
	//

	private long KeUserCallbackDispatcher;   // address in ntdll

	//
	// Addresses of various kernel data structures and lists
	// that are of interest to the kernel debugger.
	//

	private long PsLoadedModuleList;
	private long PsActiveProcessHead;
	private long PspCidTable;

	private long ExpSystemResourcesList;
	private long ExpPagedPoolDescriptor;
	private long ExpNumberOfPagedPools;

	private long KeTimeIncrement;
	private long KeBugCheckCallbackListHead;
	private long KiBugcheckData;

	private long IopErrorLogListHead;

	private long ObpRootDirectoryObject;
	private long ObpTypeObjectType;

	private long MmSystemCacheStart;
	private long MmSystemCacheEnd;
	private long MmSystemCacheWs;

	private long MmPfnDatabase;
	private long MmSystemPtesStart;
	private long MmSystemPtesEnd;
	private long MmSubsectionBase;
	private long MmNumberOfPagingFiles;

	private long MmLowestPhysicalPage;
	private long MmHighestPhysicalPage;
	private long MmNumberOfPhysicalPages;

	private long MmMaximumNonPagedPoolInBytes;
	private long MmNonPagedSystemStart;
	private long MmNonPagedPoolStart;
	private long MmNonPagedPoolEnd;

	private long MmPagedPoolStart;
	private long MmPagedPoolEnd;
	private long MmPagedPoolInformation;
	private long MmPageSize;

	private long MmSizeOfPagedPoolInBytes;

	private long MmTotalCommitLimit;
	private long MmTotalCommittedPages;
	private long MmSharedCommit;
	private long MmDriverCommit;
	private long MmProcessCommit;
	private long MmPagedPoolCommit;
	private long MmExtendedCommit;

	private long MmZeroedPageListHead;
	private long MmFreePageListHead;
	private long MmStandbyPageListHead;
	private long MmModifiedPageListHead;
	private long MmModifiedNoWritePageListHead;
	private long MmAvailablePages;
	private long MmResidentAvailablePages;

	private long PoolTrackTable;
	private long NonPagedPoolDescriptor;

	private long MmHighestUserAddress;
	private long MmSystemRangeStart;
	private long MmUserProbeAddress;

	private long KdPrintCircularBuffer;
	private long KdPrintCircularBufferEnd;
	private long KdPrintWritePointer;
	private long KdPrintRolloverCount;

	private long MmLoadedUserImageList;

	// NT 5.1 Addition

	private long NtBuildLab;
	private long KiNormalSystemCall;

	// NT 5.0 hotfix addition

	private long KiProcessorBlock;
	private long MmUnloadedDrivers;
	private long MmLastUnloadedDriver;
	private long MmTriageActionTaken;
	private long MmSpecialPoolTag;
	private long KernelVerifier;
	private long MmVerifierData;
	private long MmAllocatedNonPagedPool;
	private long MmPeakCommitment;
	private long MmTotalCommitLimitMaximum;
	private long CmNtCSDVersion;

	// NT 5.1 Addition

	private long MmPhysicalMemoryBlock;
	private long MmSessionBase;
	private long MmSessionSize;
	private long MmSystemParentTablePage;

	// Server 2003 addition

	private long MmVirtualTranslationBase;

	private short OffsetKThreadNextProcessor;
	private short OffsetKThreadTeb;
	private short OffsetKThreadKernelStack;
	private short OffsetKThreadInitialStack;

	private short OffsetKThreadApcProcess;
	private short OffsetKThreadState;
	private short OffsetKThreadBStore;
	private short OffsetKThreadBStoreLimit;

	private short SizeEProcess;
	private short OffsetEprocessPeb;
	private short OffsetEprocessParentCID;
	private short OffsetEprocessDirectoryTableBase;

	private short SizePrcb;
	private short OffsetPrcbDpcRoutine;
	private short OffsetPrcbCurrentThread;
	private short OffsetPrcbMhz;

	private short OffsetPrcbCpuType;
	private short OffsetPrcbVendorString;
	private short OffsetPrcbProcStateContext;
	private short OffsetPrcbNumber;

	private short SizeEThread;

	private byte L1tfHighPhysicalBitIndex;  // Windows 10 19H1 Addition
	private byte L1tfSwizzleBitIndex;       // Windows 10 19H1 Addition

	private int Padding0;

	private long KdPrintCircularBufferPtr;
	private long KdPrintBufferSize;

	private long KeLoaderBlock;

	private short SizePcr;
	private short OffsetPcrSelfPcr;
	private short OffsetPcrCurrentPrcb;
	private short OffsetPcrContainedPrcb;

	private short OffsetPcrInitialBStore;
	private short OffsetPcrBStoreLimit;
	private short OffsetPcrInitialStack;
	private short OffsetPcrStackLimit;

	private short OffsetPrcbPcrPage;
	private short OffsetPrcbProcStateSpecialReg;
	private short GdtR0Code;
	private short GdtR0Data;

	private short GdtR0Pcr;
	private short GdtR3Code;
	private short GdtR3Data;
	private short GdtR3Teb;

	private short GdtLdt;
	private short GdtTss;
	private short Gdt64R3CmCode;
	private short Gdt64R3CmTeb;

	private long IopNumTriageDumpDataBlocks;
	private long IopTriageDumpDataBlocks;

	// Longhorn addition

	private long VfCrashDataBlock;
	private long MmBadPagesDetected;
	private long MmZeroedPageSingleBitErrorsDetected;

	// Windows 7 addition

	private long EtwpDebuggerData;
	private short OffsetPrcbContext;

	// Windows 8 addition

	private short OffsetPrcbMaxBreakpoints;
	private short OffsetPrcbMaxWatchpoints;

	private int OffsetKThreadStackLimit;
	private int OffsetKThreadStackBase;
	private int OffsetKThreadQueueListEntry;
	private int OffsetEThreadIrpList;

	private short OffsetPrcbIdleThread;
	private short OffsetPrcbNormalDpcState;
	private short OffsetPrcbDpcStack;
	private short OffsetPrcbIsrStack;

	private short SizeKDPC_STACK_FRAME;

	// Windows 8.1 Addition

	private short OffsetKPriQueueThreadListHead;
	private short OffsetKThreadWaitReason;

	// Windows 10 RS1 Addition

	private short Padding1;
	private long PteBase;

	// Windows 10 RS5 Addition

	private long RetpolineStubFunctionTable;
	private int RetpolineStubFunctionTableSize;
	private int RetpolineStubOffset;
	private int RetpolineStubSize;

	// Windows 10 Iron Addition

	private short OffsetEProcessMmHotPatchContext;

	private DumpFileReader reader;
	private long index;
	private int psz;
	private boolean is32Bit;

	KdDebuggerData(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.psz = reader.getPointerSize();
		this.is32Bit = psz == 4;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setList_Flink(reader.readNextPointer());
		setList_Blink(reader.readNextPointer());

		//
		// This is a unique tag to identify the owner of the block.
		// If your component only uses one pool tag, use it for this, too.
		//

		setOwnerTag(reader.readNextInt());

		//
		// This must be initialized to the size of the data block,
		// including this structure.
		//

		setSize(reader.readNextInt());

		//
		// Base address of kernel image
		//

		setKernBase(reader.readNextPointer());

		//
		// DbgBreakPointWithStatus is a function which takes an argument
		// and hits a breakpoint.  This field contains the address of the
		// breakpoint instruction.  When the debugger sees a breakpoint
		// at this address, it may retrieve the argument from the first
		// argument register, or on x86 the eax register.
		//

		setBreakpointWithStatus(reader.readNextPointer());

		//
		// Address of the saved context record during a bugcheck
		//
		// N.B. This is an automatic in KeBugcheckEx's frame, and
		// is only valid after a bugcheck.
		//

		setSavedContext(reader.readNextPointer());

		//
		// help for walking stacks with user callbacks:
		//

		//
		// The address of the thread structure is provided in the
		// WAIT_STATE_CHANGE packet.  This is the offset from the base of
		// the thread structure to the pointer to the kernel stack frame
		// for the currently active usermode callback.
		//

		setThCallbackStack(reader.readNextShort());            // offset in thread data

		//
		// these values are offsets into that frame:
		//

		setNextCallback(reader.readNextShort());               // saved pointer to next callback frame
		setFramePointer(reader.readNextShort());               // saved frame pointer

		//
		// pad to a quad boundary
		//

		/*
		 PaeEnabled:1;
		 KiBugCheckRecoveryActive:1; // Windows 10 Manganese Addition
		 PagingLevels:4;
		*/
		setFlags(reader.readNextShort());

		//
		// Address of the kernel callout routine.
		//

		setKiCallUserMode(reader.readNextPointer());             // kernel routine

		//
		// Address of the usermode entry point for callbacks.
		//

		setKeUserCallbackDispatcher(reader.readNextPointer());   // address in ntdll

		//
		// Addresses of various kernel data structures and lists
		// that are of interest to the kernel debugger.
		//

		setPsLoadedModuleList(reader.readNextPointer());
		setPsActiveProcessHead(reader.readNextPointer());
		setPspCidTable(reader.readNextPointer());

		setExpSystemResourcesList(reader.readNextPointer());
		setExpPagedPoolDescriptor(reader.readNextPointer());
		setExpNumberOfPagedPools(reader.readNextPointer());

		setKeTimeIncrement(reader.readNextPointer());
		setKeBugCheckCallbackListHead(reader.readNextPointer());
		setKiBugcheckData(reader.readNextPointer());

		setIopErrorLogListHead(reader.readNextPointer());

		setObpRootDirectoryObject(reader.readNextPointer());
		setObpTypeObjectType(reader.readNextPointer());

		setMmSystemCacheStart(reader.readNextPointer());
		setMmSystemCacheEnd(reader.readNextPointer());
		setMmSystemCacheWs(reader.readNextPointer());

		setMmPfnDatabase(reader.readNextPointer());
		setMmSystemPtesStart(reader.readNextPointer());
		setMmSystemPtesEnd(reader.readNextPointer());
		setMmSubsectionBase(reader.readNextPointer());
		setMmNumberOfPagingFiles(reader.readNextPointer());

		setMmLowestPhysicalPage(reader.readNextPointer());
		setMmHighestPhysicalPage(reader.readNextPointer());
		setMmNumberOfPhysicalPages(reader.readNextPointer());

		setMmMaximumNonPagedPoolInBytes(reader.readNextPointer());
		setMmNonPagedSystemStart(reader.readNextPointer());
		setMmNonPagedPoolStart(reader.readNextPointer());
		setMmNonPagedPoolEnd(reader.readNextPointer());

		setMmPagedPoolStart(reader.readNextPointer());
		setMmPagedPoolEnd(reader.readNextPointer());
		setMmPagedPoolInformation(reader.readNextPointer());
		setMmPageSize(reader.readNextPointer());

		setMmSizeOfPagedPoolInBytes(reader.readNextPointer());

		setMmTotalCommitLimit(reader.readNextPointer());
		setMmTotalCommittedPages(reader.readNextPointer());
		setMmSharedCommit(reader.readNextPointer());
		setMmDriverCommit(reader.readNextPointer());
		setMmProcessCommit(reader.readNextPointer());
		setMmPagedPoolCommit(reader.readNextPointer());
		setMmExtendedCommit(reader.readNextPointer());

		setMmZeroedPageListHead(reader.readNextPointer());
		setMmFreePageListHead(reader.readNextPointer());
		setMmStandbyPageListHead(reader.readNextPointer());
		setMmModifiedPageListHead(reader.readNextPointer());
		setMmModifiedNoWritePageListHead(reader.readNextPointer());
		setMmAvailablePages(reader.readNextPointer());
		setMmResidentAvailablePages(reader.readNextPointer());

		setPoolTrackTable(reader.readNextPointer());
		setNonPagedPoolDescriptor(reader.readNextPointer());

		setMmHighestUserAddress(reader.readNextPointer());
		setMmSystemRangeStart(reader.readNextPointer());
		setMmUserProbeAddress(reader.readNextPointer());

		setKdPrintCircularBuffer(reader.readNextPointer());
		setKdPrintCircularBufferEnd(reader.readNextPointer());
		setKdPrintWritePointer(reader.readNextPointer());
		setKdPrintRolloverCount(reader.readNextPointer());

		setMmLoadedUserImageList(reader.readNextPointer());

		if (is32Bit) {
			return;
		}

		// NT 5.1 Addition

		setNtBuildLab(reader.readNextPointer());
		setKiNormalSystemCall(reader.readNextPointer());

		// NT 5.0 hotfix addition

		setKiProcessorBlock(reader.readNextPointer());
		setMmUnloadedDrivers(reader.readNextPointer());
		setMmLastUnloadedDriver(reader.readNextPointer());
		setMmTriageActionTaken(reader.readNextPointer());
		setMmSpecialPoolTag(reader.readNextPointer());
		setKernelVerifier(reader.readNextPointer());
		setMmVerifierData(reader.readNextPointer());
		setMmAllocatedNonPagedPool(reader.readNextPointer());
		setMmPeakCommitment(reader.readNextPointer());
		setMmTotalCommitLimitMaximum(reader.readNextPointer());
		setCmNtCSDVersion(reader.readNextPointer());

		// NT 5.1 Addition

		setMmPhysicalMemoryBlock(reader.readNextPointer());
		setMmSessionBase(reader.readNextPointer());
		setMmSessionSize(reader.readNextPointer());
		setMmSystemParentTablePage(reader.readNextPointer());

		// Server 2003 addition

		setMmVirtualTranslationBase(reader.readNextPointer());

		setOffsetKThreadNextProcessor(reader.readNextShort());
		setOffsetKThreadTeb(reader.readNextShort());
		setOffsetKThreadKernelStack(reader.readNextShort());
		setOffsetKThreadInitialStack(reader.readNextShort());

		setOffsetKThreadApcProcess(reader.readNextShort());
		setOffsetKThreadState(reader.readNextShort());
		setOffsetKThreadBStore(reader.readNextShort());
		setOffsetKThreadBStoreLimit(reader.readNextShort());

		setSizeEProcess(reader.readNextShort());
		setOffsetEprocessPeb(reader.readNextShort());
		setOffsetEprocessParentCID(reader.readNextShort());
		setOffsetEprocessDirectoryTableBase(reader.readNextShort());

		setSizePrcb(reader.readNextShort());
		setOffsetPrcbDpcRoutine(reader.readNextShort());
		setOffsetPrcbCurrentThread(reader.readNextShort());
		setOffsetPrcbMhz(reader.readNextShort());

		setOffsetPrcbCpuType(reader.readNextShort());
		setOffsetPrcbVendorString(reader.readNextShort());
		setOffsetPrcbProcStateContext(reader.readNextShort());
		setOffsetPrcbNumber(reader.readNextShort());

		setSizeEThread(reader.readNextShort());

		setL1tfHighPhysicalBitIndex(reader.readNextByte());  // Windows 10 19H1 Addition
		setL1tfSwizzleBitIndex(reader.readNextByte());       // Windows 10 19H1 Addition

		setPadding0(reader.readNextInt());

		setKdPrintCircularBufferPtr(reader.readNextPointer());
		setKdPrintBufferSize(reader.readNextPointer());

		setKeLoaderBlock(reader.readNextPointer());

		setSizePcr(reader.readNextShort());
		setOffsetPcrSelfPcr(reader.readNextShort());
		setOffsetPcrCurrentPrcb(reader.readNextShort());
		setOffsetPcrContainedPrcb(reader.readNextShort());

		setOffsetPcrInitialBStore(reader.readNextShort());
		setOffsetPcrBStoreLimit(reader.readNextShort());
		setOffsetPcrInitialStack(reader.readNextShort());
		setOffsetPcrStackLimit(reader.readNextShort());

		setOffsetPrcbPcrPage(reader.readNextShort());
		setOffsetPrcbProcStateSpecialReg(reader.readNextShort());
		setGdtR0Code(reader.readNextShort());
		setGdtR0Data(reader.readNextShort());

		setGdtR0Pcr(reader.readNextShort());
		setGdtR3Code(reader.readNextShort());
		setGdtR3Data(reader.readNextShort());
		setGdtR3Teb(reader.readNextShort());

		setGdtLdt(reader.readNextShort());
		setGdtTss(reader.readNextShort());
		setGdt64R3CmCode(reader.readNextShort());
		setGdt64R3CmTeb(reader.readNextShort());

		setIopNumTriageDumpDataBlocks(reader.readNextPointer());
		setIopTriageDumpDataBlocks(reader.readNextPointer());

		// Longhorn addition

		setVfCrashDataBlock(reader.readNextPointer());
		setMmBadPagesDetected(reader.readNextPointer());
		setMmZeroedPageSingleBitErrorsDetected(reader.readNextPointer());

		// Windows 7 addition

		setEtwpDebuggerData(reader.readNextPointer());
		setOffsetPrcbContext(reader.readNextShort());

		// Windows 8 addition

		setOffsetPrcbMaxBreakpoints(reader.readNextShort());
		setOffsetPrcbMaxWatchpoints(reader.readNextShort());

		setOffsetKThreadStackLimit(reader.readNextInt());
		setOffsetKThreadStackBase(reader.readNextInt());
		setOffsetKThreadQueueListEntry(reader.readNextInt());
		setOffsetEThreadIrpList(reader.readNextInt());

		setOffsetPrcbIdleThread(reader.readNextShort());
		setOffsetPrcbNormalDpcState(reader.readNextShort());
		setOffsetPrcbDpcStack(reader.readNextShort());
		setOffsetPrcbIsrStack(reader.readNextShort());

		setSizeKDPC_STACK_FRAME(reader.readNextShort());

		// Windows 8.1 Addition

		setOffsetKPriQueueThreadListHead(reader.readNextShort());
		setOffsetKThreadWaitReason(reader.readNextShort());

		// Windows 10 RS1 Addition

		setPadding1(reader.readNextShort());
		setPteBase(reader.readNextPointer());

		// Windows 10 RS5 Addition

		setRetpolineStubFunctionTable(reader.readNextPointer());
		setRetpolineStubFunctionTableSize(reader.readNextInt());
		setRetpolineStubOffset(reader.readNextInt());
		setRetpolineStubSize(reader.readNextInt());

		// Windows 10 Iron Addition

		setOffsetEProcessMmHotPatchContext(reader.readNextShort());

	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(QWORD, 8, "List.Flink", null);
		struct.add(QWORD, 8, "List.Blink", null);

		//
		// This is a unique tag to identify the owner of the block.
		// If your component only uses one pool tag, use it for this, too.
		//

		struct.add(STRING, 4, "OwnerTag", null);

		//
		// This must be initialized to the size of the data block,
		// including this structure.
		//

		struct.add(DWORD, 4, "Size", null);

		//
		// Base address of kernel image
		//

		struct.add(QWORD, 8, "KernBase", null);

		//
		// DbgBreakPointWithStatus is a function which takes an argument
		// and hits a breakpoint.  This field contains the address of the
		// breakpoint instruction.  When the debugger sees a breakpoint
		// at this address, it may retrieve the argument from the first
		// argument register, or on x86 the eax register.
		//

		struct.add(QWORD, 8, "BreakpointWithStatus", null);       // address of breakpoint

		//
		// Address of the saved context record during a bugcheck
		//
		// N.B. This is an automatic in KeBugcheckEx's frame, and
		// is only valid after a bugcheck.
		//

		struct.add(QWORD, 8, "SavedContext", null);

		//
		// help for walking stacks with user callbacks:
		//

		//
		// The address of the thread structure is provided in the
		// WAIT_STATE_CHANGE packet.  This is the offset from the base of
		// the thread structure to the pointer to the kernel stack frame
		// for the currently active usermode callback.
		//

		struct.add(WORD, 2, "ThCallbackStack", null);            // offset in thread data

		//
		// these values are offsets into that frame:
		//

		struct.add(WORD, 2, "NextCallback", null);               // saved pointer to next callback frame
		struct.add(WORD, 2, "FramePointer", null);               // saved frame pointer

		//
		// pad to a quad boundary
		//
		/*
		struct.add(WORD, 2, "PaeEnabled:1", null);
		struct.add(WORD, 2, "KiBugCheckRecoveryActive:1", null); // Windows 10 Manganese Addition
		struct.add(WORD, 2, "PagingLevels:4", null);
		*/
		struct.add(WORD, 2, "Flags", null);

		//
		// Address of the kernel callout routine.
		//

		struct.add(POINTER, psz, "KiCallUserMode", null);             // kernel routine

		//
		// Address of the usermode entry point for callbacks.
		//

		struct.add(POINTER, psz, "KeUserCallbackDispatcher", null);   // address in ntdll

		//
		// Addresses of various kernel data structures and lists
		// that are of interest to the kernel debugger.
		//

		struct.add(POINTER, psz, "PsLoadedModuleList", null);
		struct.add(POINTER, psz, "PsActiveProcessHead", null);
		struct.add(POINTER, psz, "PspCidTable", null);

		struct.add(POINTER, psz, "ExpSystemResourcesList", null);
		struct.add(POINTER, psz, "ExpPagedPoolDescriptor", null);
		struct.add(POINTER, psz, "ExpNumberOfPagedPools", null);

		struct.add(POINTER, psz, "KeTimeIncrement", null);
		struct.add(POINTER, psz, "KeBugCheckCallbackListHead", null);
		struct.add(POINTER, psz, "KiBugcheckData", null);

		struct.add(POINTER, psz, "IopErrorLogListHead", null);

		struct.add(POINTER, psz, "ObpRootDirectoryObject", null);
		struct.add(POINTER, psz, "ObpTypeObjectType", null);

		struct.add(POINTER, psz, "MmSystemCacheStart", null);
		struct.add(POINTER, psz, "MmSystemCacheEnd", null);
		struct.add(POINTER, psz, "MmSystemCacheWs", null);

		struct.add(POINTER, psz, "MmPfnDatabase", null);
		struct.add(POINTER, psz, "MmSystemPtesStart", null);
		struct.add(POINTER, psz, "MmSystemPtesEnd", null);
		struct.add(POINTER, psz, "MmSubsectionBase", null);
		struct.add(POINTER, psz, "MmNumberOfPagingFiles", null);

		struct.add(POINTER, psz, "MmLowestPhysicalPage", null);
		struct.add(POINTER, psz, "MmHighestPhysicalPage", null);
		struct.add(POINTER, psz, "MmNumberOfPhysicalPages", null);

		struct.add(POINTER, psz, "MmMaximumNonPagedPoolInBytes", null);
		struct.add(POINTER, psz, "MmNonPagedSystemStart", null);
		struct.add(POINTER, psz, "MmNonPagedPoolStart", null);
		struct.add(POINTER, psz, "MmNonPagedPoolEnd", null);

		struct.add(POINTER, psz, "MmPagedPoolStart", null);
		struct.add(POINTER, psz, "MmPagedPoolEnd", null);
		struct.add(POINTER, psz, "MmPagedPoolInformation", null);
		struct.add(QWORD, psz, "MmPageSize", null);

		struct.add(POINTER, psz, "MmSizeOfPagedPoolInBytes", null);

		struct.add(POINTER, psz, "MmTotalCommitLimit", null);
		struct.add(POINTER, psz, "MmTotalCommittedPages", null);
		struct.add(POINTER, psz, "MmSharedCommit", null);
		struct.add(POINTER, psz, "MmDriverCommit", null);
		struct.add(POINTER, psz, "MmProcessCommit", null);
		struct.add(POINTER, psz, "MmPagedPoolCommit", null);
		struct.add(POINTER, psz, "MmExtendedCommit", null);

		struct.add(POINTER, psz, "MmZeroedPageListHead", null);
		struct.add(POINTER, psz, "MmFreePageListHead", null);
		struct.add(POINTER, psz, "MmStandbyPageListHead", null);
		struct.add(POINTER, psz, "MmModifiedPageListHead", null);
		struct.add(POINTER, psz, "MmModifiedNoWritePageListHead", null);
		struct.add(POINTER, psz, "MmAvailablePages", null);
		struct.add(POINTER, psz, "MmResidentAvailablePages", null);

		struct.add(POINTER, psz, "PoolTrackTable", null);
		struct.add(POINTER, psz, "NonPagedPoolDescriptor", null);

		struct.add(POINTER, psz, "MmHighestUserAddress", null);
		struct.add(POINTER, psz, "MmSystemRangeStart", null);
		struct.add(POINTER, psz, "MmUserProbeAddress", null);

		struct.add(POINTER, psz, "KdPrintCircularBuffer", null);
		struct.add(POINTER, psz, "KdPrintCircularBufferEnd", null);
		struct.add(POINTER, psz, "KdPrintWritePointer", null);
		struct.add(POINTER, psz, "KdPrintRolloverCount", null);

		struct.add(POINTER, psz, "MmLoadedUserImageList", null);

		if (is32Bit) {
			return struct;
		}

		// NT 5.1 Addition

		struct.add(POINTER, psz, "NtBuildLab", null);
		struct.add(POINTER, psz, "KiNormalSystemCall", null);

		// NT 5.0 hotfix addition

		struct.add(POINTER, psz, "KiProcessorBlock", null);
		struct.add(POINTER, psz, "MmUnloadedDrivers", null);
		struct.add(POINTER, psz, "MmLastUnloadedDriver", null);
		struct.add(POINTER, psz, "MmTriageActionTaken", null);
		struct.add(POINTER, psz, "MmSpecialPoolTag", null);
		struct.add(POINTER, psz, "KernelVerifier", null);
		struct.add(POINTER, psz, "MmVerifierData", null);
		struct.add(POINTER, psz, "MmAllocatedNonPagedPool", null);
		struct.add(POINTER, psz, "MmPeakCommitment", null);
		struct.add(POINTER, psz, "MmTotalCommitLimitMaximum", null);
		struct.add(POINTER, psz, "CmNtCSDVersion", null);

		// NT 5.1 Addition

		struct.add(POINTER, psz, "MmPhysicalMemoryBlock", null);
		struct.add(POINTER, psz, "MmSessionBase", null);
		struct.add(POINTER, psz, "MmSessionSize", null);
		struct.add(POINTER, psz, "MmSystemParentTablePage", null);

		// Server 2003 addition

		struct.add(POINTER, psz, "MmVirtualTranslationBase", null);

		struct.add(WORD, 2, "OffsetKThreadNextProcessor", null);
		struct.add(WORD, 2, "OffsetKThreadTeb", null);
		struct.add(WORD, 2, "OffsetKThreadKernelStack", null);
		struct.add(WORD, 2, "OffsetKThreadInitialStack", null);

		struct.add(WORD, 2, "OffsetKThreadApcProcess", null);
		struct.add(WORD, 2, "OffsetKThreadState", null);
		struct.add(WORD, 2, "OffsetKThreadBStore", null);
		struct.add(WORD, 2, "OffsetKThreadBStoreLimit", null);

		struct.add(WORD, 2, "SizeEProcess", null);
		struct.add(WORD, 2, "OffsetEprocessPeb", null);
		struct.add(WORD, 2, "OffsetEprocessParentCID", null);
		struct.add(WORD, 2, "OffsetEprocessDirectoryTableBase", null);

		struct.add(WORD, 2, "SizePrcb", null);
		struct.add(WORD, 2, "OffsetPrcbDpcRoutine", null);
		struct.add(WORD, 2, "OffsetPrcbCurrentThread", null);
		struct.add(WORD, 2, "OffsetPrcbMhz", null);

		struct.add(WORD, 2, "OffsetPrcbCpuType", null);
		struct.add(WORD, 2, "OffsetPrcbVendorString", null);
		struct.add(WORD, 2, "OffsetPrcbProcStateContext", null);
		struct.add(WORD, 2, "OffsetPrcbNumber", null);

		struct.add(WORD, 2, "SizeEThread", null);

		struct.add(BYTE, "L1tfHighPhysicalBitIndex", null);  // Windows 10 19H1 Addition
		struct.add(BYTE, "L1tfSwizzleBitIndex", null);       // Windows 10 19H1 Addition

		struct.add(DWORD, 4, "Padding0", null);

		struct.add(POINTER, psz, "KdPrintCircularBufferPtr", null);
		struct.add(POINTER, psz, "KdPrintBufferSize", null);

		struct.add(POINTER, psz, "KeLoaderBlock", null);

		struct.add(WORD, 2, "SizePcr", null);
		struct.add(WORD, 2, "OffsetPcrSelfPcr", null);
		struct.add(WORD, 2, "OffsetPcrCurrentPrcb", null);
		struct.add(WORD, 2, "OffsetPcrContainedPrcb", null);

		struct.add(WORD, 2, "OffsetPcrInitialBStore", null);
		struct.add(WORD, 2, "OffsetPcrBStoreLimit", null);
		struct.add(WORD, 2, "OffsetPcrInitialStack", null);
		struct.add(WORD, 2, "OffsetPcrStackLimit", null);

		struct.add(WORD, 2, "OffsetPrcbPcrPage", null);
		struct.add(WORD, 2, "OffsetPrcbProcStateSpecialReg", null);
		struct.add(WORD, 2, "GdtR0Code", null);
		struct.add(WORD, 2, "GdtR0Data", null);

		struct.add(WORD, 2, "GdtR0Pcr", null);
		struct.add(WORD, 2, "GdtR3Code", null);
		struct.add(WORD, 2, "GdtR3Data", null);
		struct.add(WORD, 2, "GdtR3Teb", null);

		struct.add(WORD, 2, "GdtLdt", null);
		struct.add(WORD, 2, "GdtTss", null);
		struct.add(WORD, 2, "Gdt64R3CmCode", null);
		struct.add(WORD, 2, "Gdt64R3CmTeb", null);

		struct.add(POINTER, psz, "IopNumTriageDumpDataBlocks", null);
		struct.add(POINTER, psz, "IopTriageDumpDataBlocks", null);

		// Longhorn addition

		struct.add(POINTER, psz, "VfCrashDataBlock", null);
		struct.add(POINTER, psz, "MmBadPagesDetected", null);
		struct.add(POINTER, psz, "MmZeroedPageSingleBitErrorsDetected", null);

		// Windows 7 addition

		struct.add(POINTER, psz, "EtwpDebuggerData", null);
		struct.add(WORD, 2, "OffsetPrcbContext", null);

		// Windows 8 addition

		struct.add(WORD, 2, "OffsetPrcbMaxBreakpoints", null);
		struct.add(WORD, 2, "OffsetPrcbMaxWatchpoints", null);

		struct.add(DWORD, 4, "OffsetKThreadStackLimit", null);
		struct.add(DWORD, 4, "OffsetKThreadStackBase", null);
		struct.add(DWORD, 4, "OffsetKThreadQueueListEntry", null);
		struct.add(DWORD, 4, "OffsetEThreadIrpList", null);

		struct.add(WORD, 2, "OffsetPrcbIdleThread", null);
		struct.add(WORD, 2, "OffsetPrcbNormalDpcState", null);
		struct.add(WORD, 2, "OffsetPrcbDpcStack", null);
		struct.add(WORD, 2, "OffsetPrcbIsrStack", null);

		struct.add(WORD, 2, "SizeKDPC_STACK_FRAME", null);

		// Windows 8.1 Addition

		struct.add(WORD, 2, "OffsetKPriQueueThreadListHead", null);
		struct.add(WORD, 2, "OffsetKThreadWaitReason", null);

		// Windows 10 RS1 Addition

		struct.add(WORD, 2, "Padding1", null);
		struct.add(QWORD, psz, "PteBase", null);

		// Windows 10 RS5 Addition

		struct.add(QWORD, psz, "RetpolineStubFunctionTable", null);
		struct.add(DWORD, 4, "RetpolineStubFunctionTableSize", null);
		struct.add(DWORD, 4, "RetpolineStubOffset", null);
		struct.add(DWORD, 4, "RetpolineStubSize", null);

		// Windows 10 Iron Addition

		struct.add(WORD, 2, "OffsetEProcessMmHotPatchContext", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public long getList_Flink() {
		return List_Flink;
	}

	public void setList_Flink(long list_Flink) {
		List_Flink = list_Flink;
	}

	public long getList_Blink() {
		return List_Blink;
	}

	public void setList_Blink(long list_Blink) {
		List_Blink = list_Blink;
	}

	public int getOwnerTag() {
		return OwnerTag;
	}

	public void setOwnerTag(int ownerTag) {
		OwnerTag = ownerTag;
	}

	public int getSize() {
		return Size;
	}

	public void setSize(int size) {
		Size = size;
	}

	public long getKernBase() {
		return KernBase;
	}

	public void setKernBase(long kernBase) {
		KernBase = kernBase;
	}

	public long getBreakpointWithStatus() {
		return BreakpointWithStatus;
	}

	public void setBreakpointWithStatus(long breakpointWithStatus) {
		BreakpointWithStatus = breakpointWithStatus;
	}

	public long getSavedContext() {
		return SavedContext;
	}

	public void setSavedContext(long savedContext) {
		SavedContext = savedContext;
	}

	public short getThCallbackStack() {
		return ThCallbackStack;
	}

	public void setThCallbackStack(short thCallbackStack) {
		ThCallbackStack = thCallbackStack;
	}

	public short getNextCallback() {
		return NextCallback;
	}

	public void setNextCallback(short nextCallback) {
		NextCallback = nextCallback;
	}

	public short getFramePointer() {
		return FramePointer;
	}

	public void setFramePointer(short framePointer) {
		FramePointer = framePointer;
	}

	public short getFlags() {
		return Flags;
	}

	public void setFlags(short flags) {
		Flags = flags;
	}

	public long getKiCallUserMode() {
		return KiCallUserMode;
	}

	public void setKiCallUserMode(long kiCallUserMode) {
		KiCallUserMode = kiCallUserMode;
	}

	public long getKeUserCallbackDispatcher() {
		return KeUserCallbackDispatcher;
	}

	public void setKeUserCallbackDispatcher(long keUserCallbackDispatcher) {
		KeUserCallbackDispatcher = keUserCallbackDispatcher;
	}

	public long getPsLoadedModuleList() {
		return PsLoadedModuleList;
	}

	public void setPsLoadedModuleList(long psLoadedModuleList) {
		PsLoadedModuleList = psLoadedModuleList;
	}

	public long getPsActiveProcessHead() {
		return PsActiveProcessHead;
	}

	public void setPsActiveProcessHead(long psActiveProcessHead) {
		PsActiveProcessHead = psActiveProcessHead;
	}

	public long getPspCidTable() {
		return PspCidTable;
	}

	public void setPspCidTable(long pspCidTable) {
		PspCidTable = pspCidTable;
	}

	public long getExpSystemResourcesList() {
		return ExpSystemResourcesList;
	}

	public void setExpSystemResourcesList(long expSystemResourcesList) {
		ExpSystemResourcesList = expSystemResourcesList;
	}

	public long getExpPagedPoolDescriptor() {
		return ExpPagedPoolDescriptor;
	}

	public void setExpPagedPoolDescriptor(long expPagedPoolDescriptor) {
		ExpPagedPoolDescriptor = expPagedPoolDescriptor;
	}

	public long getExpNumberOfPagedPools() {
		return ExpNumberOfPagedPools;
	}

	public void setExpNumberOfPagedPools(long expNumberOfPagedPools) {
		ExpNumberOfPagedPools = expNumberOfPagedPools;
	}

	public long getKeTimeIncrement() {
		return KeTimeIncrement;
	}

	public void setKeTimeIncrement(long keTimeIncrement) {
		KeTimeIncrement = keTimeIncrement;
	}

	public long getKeBugCheckCallbackListHead() {
		return KeBugCheckCallbackListHead;
	}

	public void setKeBugCheckCallbackListHead(long keBugCheckCallbackListHead) {
		KeBugCheckCallbackListHead = keBugCheckCallbackListHead;
	}

	public long getKiBugcheckData() {
		return KiBugcheckData;
	}

	public void setKiBugcheckData(long kiBugcheckData) {
		KiBugcheckData = kiBugcheckData;
	}

	public long getIopErrorLogListHead() {
		return IopErrorLogListHead;
	}

	public void setIopErrorLogListHead(long iopErrorLogListHead) {
		IopErrorLogListHead = iopErrorLogListHead;
	}

	public long getObpRootDirectoryObject() {
		return ObpRootDirectoryObject;
	}

	public void setObpRootDirectoryObject(long obpRootDirectoryObject) {
		ObpRootDirectoryObject = obpRootDirectoryObject;
	}

	public long getObpTypeObjectType() {
		return ObpTypeObjectType;
	}

	public void setObpTypeObjectType(long obpTypeObjectType) {
		ObpTypeObjectType = obpTypeObjectType;
	}

	public long getMmSystemCacheStart() {
		return MmSystemCacheStart;
	}

	public void setMmSystemCacheStart(long mmSystemCacheStart) {
		MmSystemCacheStart = mmSystemCacheStart;
	}

	public long getMmSystemCacheEnd() {
		return MmSystemCacheEnd;
	}

	public void setMmSystemCacheEnd(long mmSystemCacheEnd) {
		MmSystemCacheEnd = mmSystemCacheEnd;
	}

	public long getMmSystemCacheWs() {
		return MmSystemCacheWs;
	}

	public void setMmSystemCacheWs(long mmSystemCacheWs) {
		MmSystemCacheWs = mmSystemCacheWs;
	}

	public long getMmPfnDatabase() {
		return MmPfnDatabase;
	}

	public void setMmPfnDatabase(long mmPfnDatabase) {
		MmPfnDatabase = mmPfnDatabase;
	}

	public long getMmSystemPtesStart() {
		return MmSystemPtesStart;
	}

	public void setMmSystemPtesStart(long mmSystemPtesStart) {
		MmSystemPtesStart = mmSystemPtesStart;
	}

	public long getMmSystemPtesEnd() {
		return MmSystemPtesEnd;
	}

	public void setMmSystemPtesEnd(long mmSystemPtesEnd) {
		MmSystemPtesEnd = mmSystemPtesEnd;
	}

	public long getMmSubsectionBase() {
		return MmSubsectionBase;
	}

	public void setMmSubsectionBase(long mmSubsectionBase) {
		MmSubsectionBase = mmSubsectionBase;
	}

	public long getMmNumberOfPagingFiles() {
		return MmNumberOfPagingFiles;
	}

	public void setMmNumberOfPagingFiles(long mmNumberOfPagingFiles) {
		MmNumberOfPagingFiles = mmNumberOfPagingFiles;
	}

	public long getMmLowestPhysicalPage() {
		return MmLowestPhysicalPage;
	}

	public void setMmLowestPhysicalPage(long mmLowestPhysicalPage) {
		MmLowestPhysicalPage = mmLowestPhysicalPage;
	}

	public long getMmHighestPhysicalPage() {
		return MmHighestPhysicalPage;
	}

	public void setMmHighestPhysicalPage(long mmHighestPhysicalPage) {
		MmHighestPhysicalPage = mmHighestPhysicalPage;
	}

	public long getMmNumberOfPhysicalPages() {
		return MmNumberOfPhysicalPages;
	}

	public void setMmNumberOfPhysicalPages(long mmNumberOfPhysicalPages) {
		MmNumberOfPhysicalPages = mmNumberOfPhysicalPages;
	}

	public long getMmMaximumNonPagedPoolInBytes() {
		return MmMaximumNonPagedPoolInBytes;
	}

	public void setMmMaximumNonPagedPoolInBytes(long mmMaximumNonPagedPoolInBytes) {
		MmMaximumNonPagedPoolInBytes = mmMaximumNonPagedPoolInBytes;
	}

	public long getMmNonPagedSystemStart() {
		return MmNonPagedSystemStart;
	}

	public void setMmNonPagedSystemStart(long mmNonPagedSystemStart) {
		MmNonPagedSystemStart = mmNonPagedSystemStart;
	}

	public long getMmNonPagedPoolStart() {
		return MmNonPagedPoolStart;
	}

	public void setMmNonPagedPoolStart(long mmNonPagedPoolStart) {
		MmNonPagedPoolStart = mmNonPagedPoolStart;
	}

	public long getMmNonPagedPoolEnd() {
		return MmNonPagedPoolEnd;
	}

	public void setMmNonPagedPoolEnd(long mmNonPagedPoolEnd) {
		MmNonPagedPoolEnd = mmNonPagedPoolEnd;
	}

	public long getMmPagedPoolStart() {
		return MmPagedPoolStart;
	}

	public void setMmPagedPoolStart(long mmPagedPoolStart) {
		MmPagedPoolStart = mmPagedPoolStart;
	}

	public long getMmPagedPoolEnd() {
		return MmPagedPoolEnd;
	}

	public void setMmPagedPoolEnd(long mmPagedPoolEnd) {
		MmPagedPoolEnd = mmPagedPoolEnd;
	}

	public long getMmPagedPoolInformation() {
		return MmPagedPoolInformation;
	}

	public void setMmPagedPoolInformation(long mmPagedPoolInformation) {
		MmPagedPoolInformation = mmPagedPoolInformation;
	}

	public long getMmPageSize() {
		return MmPageSize;
	}

	public void setMmPageSize(long mmPageSize) {
		MmPageSize = mmPageSize;
	}

	public long getMmSizeOfPagedPoolInBytes() {
		return MmSizeOfPagedPoolInBytes;
	}

	public void setMmSizeOfPagedPoolInBytes(long mmSizeOfPagedPoolInBytes) {
		MmSizeOfPagedPoolInBytes = mmSizeOfPagedPoolInBytes;
	}

	public long getMmTotalCommitLimit() {
		return MmTotalCommitLimit;
	}

	public void setMmTotalCommitLimit(long mmTotalCommitLimit) {
		MmTotalCommitLimit = mmTotalCommitLimit;
	}

	public long getMmTotalCommittedPages() {
		return MmTotalCommittedPages;
	}

	public void setMmTotalCommittedPages(long mmTotalCommittedPages) {
		MmTotalCommittedPages = mmTotalCommittedPages;
	}

	public long getMmSharedCommit() {
		return MmSharedCommit;
	}

	public void setMmSharedCommit(long mmSharedCommit) {
		MmSharedCommit = mmSharedCommit;
	}

	public long getMmDriverCommit() {
		return MmDriverCommit;
	}

	public void setMmDriverCommit(long mmDriverCommit) {
		MmDriverCommit = mmDriverCommit;
	}

	public long getMmProcessCommit() {
		return MmProcessCommit;
	}

	public void setMmProcessCommit(long mmProcessCommit) {
		MmProcessCommit = mmProcessCommit;
	}

	public long getMmPagedPoolCommit() {
		return MmPagedPoolCommit;
	}

	public void setMmPagedPoolCommit(long mmPagedPoolCommit) {
		MmPagedPoolCommit = mmPagedPoolCommit;
	}

	public long getMmExtendedCommit() {
		return MmExtendedCommit;
	}

	public void setMmExtendedCommit(long mmExtendedCommit) {
		MmExtendedCommit = mmExtendedCommit;
	}

	public long getMmZeroedPageListHead() {
		return MmZeroedPageListHead;
	}

	public void setMmZeroedPageListHead(long mmZeroedPageListHead) {
		MmZeroedPageListHead = mmZeroedPageListHead;
	}

	public long getMmFreePageListHead() {
		return MmFreePageListHead;
	}

	public void setMmFreePageListHead(long mmFreePageListHead) {
		MmFreePageListHead = mmFreePageListHead;
	}

	public long getMmStandbyPageListHead() {
		return MmStandbyPageListHead;
	}

	public void setMmStandbyPageListHead(long mmStandbyPageListHead) {
		MmStandbyPageListHead = mmStandbyPageListHead;
	}

	public long getMmModifiedPageListHead() {
		return MmModifiedPageListHead;
	}

	public void setMmModifiedPageListHead(long mmModifiedPageListHead) {
		MmModifiedPageListHead = mmModifiedPageListHead;
	}

	public long getMmModifiedNoWritePageListHead() {
		return MmModifiedNoWritePageListHead;
	}

	public void setMmModifiedNoWritePageListHead(long mmModifiedNoWritePageListHead) {
		MmModifiedNoWritePageListHead = mmModifiedNoWritePageListHead;
	}

	public long getMmAvailablePages() {
		return MmAvailablePages;
	}

	public void setMmAvailablePages(long mmAvailablePages) {
		MmAvailablePages = mmAvailablePages;
	}

	public long getMmResidentAvailablePages() {
		return MmResidentAvailablePages;
	}

	public void setMmResidentAvailablePages(long mmResidentAvailablePages) {
		MmResidentAvailablePages = mmResidentAvailablePages;
	}

	public long getPoolTrackTable() {
		return PoolTrackTable;
	}

	public void setPoolTrackTable(long poolTrackTable) {
		PoolTrackTable = poolTrackTable;
	}

	public long getNonPagedPoolDescriptor() {
		return NonPagedPoolDescriptor;
	}

	public void setNonPagedPoolDescriptor(long nonPagedPoolDescriptor) {
		NonPagedPoolDescriptor = nonPagedPoolDescriptor;
	}

	public long getMmHighestUserAddress() {
		return MmHighestUserAddress;
	}

	public void setMmHighestUserAddress(long mmHighestUserAddress) {
		MmHighestUserAddress = mmHighestUserAddress;
	}

	public long getMmSystemRangeStart() {
		return MmSystemRangeStart;
	}

	public void setMmSystemRangeStart(long mmSystemRangeStart) {
		MmSystemRangeStart = mmSystemRangeStart;
	}

	public long getMmUserProbeAddress() {
		return MmUserProbeAddress;
	}

	public void setMmUserProbeAddress(long mmUserProbeAddress) {
		MmUserProbeAddress = mmUserProbeAddress;
	}

	public long getKdPrintCircularBuffer() {
		return KdPrintCircularBuffer;
	}

	public void setKdPrintCircularBuffer(long kdPrintCircularBuffer) {
		KdPrintCircularBuffer = kdPrintCircularBuffer;
	}

	public long getKdPrintCircularBufferEnd() {
		return KdPrintCircularBufferEnd;
	}

	public void setKdPrintCircularBufferEnd(long kdPrintCircularBufferEnd) {
		KdPrintCircularBufferEnd = kdPrintCircularBufferEnd;
	}

	public long getKdPrintWritePointer() {
		return KdPrintWritePointer;
	}

	public void setKdPrintWritePointer(long kdPrintWritePointer) {
		KdPrintWritePointer = kdPrintWritePointer;
	}

	public long getKdPrintRolloverCount() {
		return KdPrintRolloverCount;
	}

	public void setKdPrintRolloverCount(long kdPrintRolloverCount) {
		KdPrintRolloverCount = kdPrintRolloverCount;
	}

	public long getMmLoadedUserImageList() {
		return MmLoadedUserImageList;
	}

	public void setMmLoadedUserImageList(long mmLoadedUserImageList) {
		MmLoadedUserImageList = mmLoadedUserImageList;
	}

	public long getNtBuildLab() {
		return NtBuildLab;
	}

	public void setNtBuildLab(long ntBuildLab) {
		NtBuildLab = ntBuildLab;
	}

	public long getKiNormalSystemCall() {
		return KiNormalSystemCall;
	}

	public void setKiNormalSystemCall(long kiNormalSystemCall) {
		KiNormalSystemCall = kiNormalSystemCall;
	}

	public long getKiProcessorBlock() {
		return KiProcessorBlock;
	}

	public void setKiProcessorBlock(long kiProcessorBlock) {
		KiProcessorBlock = kiProcessorBlock;
	}

	public long getMmUnloadedDrivers() {
		return MmUnloadedDrivers;
	}

	public void setMmUnloadedDrivers(long mmUnloadedDrivers) {
		MmUnloadedDrivers = mmUnloadedDrivers;
	}

	public long getMmLastUnloadedDriver() {
		return MmLastUnloadedDriver;
	}

	public void setMmLastUnloadedDriver(long mmLastUnloadedDriver) {
		MmLastUnloadedDriver = mmLastUnloadedDriver;
	}

	public long getMmTriageActionTaken() {
		return MmTriageActionTaken;
	}

	public void setMmTriageActionTaken(long mmTriageActionTaken) {
		MmTriageActionTaken = mmTriageActionTaken;
	}

	public long getMmSpecialPoolTag() {
		return MmSpecialPoolTag;
	}

	public void setMmSpecialPoolTag(long mmSpecialPoolTag) {
		MmSpecialPoolTag = mmSpecialPoolTag;
	}

	public long getKernelVerifier() {
		return KernelVerifier;
	}

	public void setKernelVerifier(long kernelVerifier) {
		KernelVerifier = kernelVerifier;
	}

	public long getMmVerifierData() {
		return MmVerifierData;
	}

	public void setMmVerifierData(long mmVerifierData) {
		MmVerifierData = mmVerifierData;
	}

	public long getMmAllocatedNonPagedPool() {
		return MmAllocatedNonPagedPool;
	}

	public void setMmAllocatedNonPagedPool(long mmAllocatedNonPagedPool) {
		MmAllocatedNonPagedPool = mmAllocatedNonPagedPool;
	}

	public long getMmPeakCommitment() {
		return MmPeakCommitment;
	}

	public void setMmPeakCommitment(long mmPeakCommitment) {
		MmPeakCommitment = mmPeakCommitment;
	}

	public long getMmTotalCommitLimitMaximum() {
		return MmTotalCommitLimitMaximum;
	}

	public void setMmTotalCommitLimitMaximum(long mmTotalCommitLimitMaximum) {
		MmTotalCommitLimitMaximum = mmTotalCommitLimitMaximum;
	}

	public long getCmNtCSDVersion() {
		return CmNtCSDVersion;
	}

	public void setCmNtCSDVersion(long cmNtCSDVersion) {
		CmNtCSDVersion = cmNtCSDVersion;
	}

	public long getMmPhysicalMemoryBlock() {
		return MmPhysicalMemoryBlock;
	}

	public void setMmPhysicalMemoryBlock(long mmPhysicalMemoryBlock) {
		MmPhysicalMemoryBlock = mmPhysicalMemoryBlock;
	}

	public long getMmSessionBase() {
		return MmSessionBase;
	}

	public void setMmSessionBase(long mmSessionBase) {
		MmSessionBase = mmSessionBase;
	}

	public long getMmSessionSize() {
		return MmSessionSize;
	}

	public void setMmSessionSize(long mmSessionSize) {
		MmSessionSize = mmSessionSize;
	}

	public long getMmSystemParentTablePage() {
		return MmSystemParentTablePage;
	}

	public void setMmSystemParentTablePage(long mmSystemParentTablePage) {
		MmSystemParentTablePage = mmSystemParentTablePage;
	}

	public long getMmVirtualTranslationBase() {
		return MmVirtualTranslationBase;
	}

	public void setMmVirtualTranslationBase(long mmVirtualTranslationBase) {
		MmVirtualTranslationBase = mmVirtualTranslationBase;
	}

	public short getOffsetKThreadNextProcessor() {
		return OffsetKThreadNextProcessor;
	}

	public void setOffsetKThreadNextProcessor(short offsetKThreadNextProcessor) {
		OffsetKThreadNextProcessor = offsetKThreadNextProcessor;
	}

	public short getOffsetKThreadTeb() {
		return OffsetKThreadTeb;
	}

	public void setOffsetKThreadTeb(short offsetKThreadTeb) {
		OffsetKThreadTeb = offsetKThreadTeb;
	}

	public short getOffsetKThreadKernelStack() {
		return OffsetKThreadKernelStack;
	}

	public void setOffsetKThreadKernelStack(short offsetKThreadKernelStack) {
		OffsetKThreadKernelStack = offsetKThreadKernelStack;
	}

	public short getOffsetKThreadInitialStack() {
		return OffsetKThreadInitialStack;
	}

	public void setOffsetKThreadInitialStack(short offsetKThreadInitialStack) {
		OffsetKThreadInitialStack = offsetKThreadInitialStack;
	}

	public short getOffsetKThreadApcProcess() {
		return OffsetKThreadApcProcess;
	}

	public void setOffsetKThreadApcProcess(short offsetKThreadApcProcess) {
		OffsetKThreadApcProcess = offsetKThreadApcProcess;
	}

	public short getOffsetKThreadState() {
		return OffsetKThreadState;
	}

	public void setOffsetKThreadState(short offsetKThreadState) {
		OffsetKThreadState = offsetKThreadState;
	}

	public short getOffsetKThreadBStore() {
		return OffsetKThreadBStore;
	}

	public void setOffsetKThreadBStore(short offsetKThreadBStore) {
		OffsetKThreadBStore = offsetKThreadBStore;
	}

	public short getOffsetKThreadBStoreLimit() {
		return OffsetKThreadBStoreLimit;
	}

	public void setOffsetKThreadBStoreLimit(short offsetKThreadBStoreLimit) {
		OffsetKThreadBStoreLimit = offsetKThreadBStoreLimit;
	}

	public short getSizeEProcess() {
		return SizeEProcess;
	}

	public void setSizeEProcess(short sizeEProcess) {
		SizeEProcess = sizeEProcess;
	}

	public short getOffsetEprocessPeb() {
		return OffsetEprocessPeb;
	}

	public void setOffsetEprocessPeb(short offsetEprocessPeb) {
		OffsetEprocessPeb = offsetEprocessPeb;
	}

	public short getOffsetEprocessParentCID() {
		return OffsetEprocessParentCID;
	}

	public void setOffsetEprocessParentCID(short offsetEprocessParentCID) {
		OffsetEprocessParentCID = offsetEprocessParentCID;
	}

	public short getOffsetEprocessDirectoryTableBase() {
		return OffsetEprocessDirectoryTableBase;
	}

	public void setOffsetEprocessDirectoryTableBase(short offsetEprocessDirectoryTableBase) {
		OffsetEprocessDirectoryTableBase = offsetEprocessDirectoryTableBase;
	}

	public short getSizePrcb() {
		return SizePrcb;
	}

	public void setSizePrcb(short sizePrcb) {
		SizePrcb = sizePrcb;
	}

	public short getOffsetPrcbDpcRoutine() {
		return OffsetPrcbDpcRoutine;
	}

	public void setOffsetPrcbDpcRoutine(short offsetPrcbDpcRoutine) {
		OffsetPrcbDpcRoutine = offsetPrcbDpcRoutine;
	}

	public short getOffsetPrcbCurrentThread() {
		return OffsetPrcbCurrentThread;
	}

	public void setOffsetPrcbCurrentThread(short offsetPrcbCurrentThread) {
		OffsetPrcbCurrentThread = offsetPrcbCurrentThread;
	}

	public short getOffsetPrcbMhz() {
		return OffsetPrcbMhz;
	}

	public void setOffsetPrcbMhz(short offsetPrcbMhz) {
		OffsetPrcbMhz = offsetPrcbMhz;
	}

	public short getOffsetPrcbCpuType() {
		return OffsetPrcbCpuType;
	}

	public void setOffsetPrcbCpuType(short offsetPrcbCpuType) {
		OffsetPrcbCpuType = offsetPrcbCpuType;
	}

	public short getOffsetPrcbVendorString() {
		return OffsetPrcbVendorString;
	}

	public void setOffsetPrcbVendorString(short offsetPrcbVendorString) {
		OffsetPrcbVendorString = offsetPrcbVendorString;
	}

	public short getOffsetPrcbProcStateContext() {
		return OffsetPrcbProcStateContext;
	}

	public void setOffsetPrcbProcStateContext(short offsetPrcbProcStateContext) {
		OffsetPrcbProcStateContext = offsetPrcbProcStateContext;
	}

	public short getOffsetPrcbNumber() {
		return OffsetPrcbNumber;
	}

	public void setOffsetPrcbNumber(short offsetPrcbNumber) {
		OffsetPrcbNumber = offsetPrcbNumber;
	}

	public short getSizeEThread() {
		return SizeEThread;
	}

	public void setSizeEThread(short sizeEThread) {
		SizeEThread = sizeEThread;
	}

	public byte getL1tfHighPhysicalBitIndex() {
		return L1tfHighPhysicalBitIndex;
	}

	public void setL1tfHighPhysicalBitIndex(byte l1tfHighPhysicalBitIndex) {
		L1tfHighPhysicalBitIndex = l1tfHighPhysicalBitIndex;
	}

	public byte getL1tfSwizzleBitIndex() {
		return L1tfSwizzleBitIndex;
	}

	public void setL1tfSwizzleBitIndex(byte l1tfSwizzleBitIndex) {
		L1tfSwizzleBitIndex = l1tfSwizzleBitIndex;
	}

	public int getPadding0() {
		return Padding0;
	}

	public void setPadding0(int padding0) {
		Padding0 = padding0;
	}

	public long getKdPrintCircularBufferPtr() {
		return KdPrintCircularBufferPtr;
	}

	public void setKdPrintCircularBufferPtr(long kdPrintCircularBufferPtr) {
		KdPrintCircularBufferPtr = kdPrintCircularBufferPtr;
	}

	public long getKdPrintBufferSize() {
		return KdPrintBufferSize;
	}

	public void setKdPrintBufferSize(long kdPrintBufferSize) {
		KdPrintBufferSize = kdPrintBufferSize;
	}

	public long getKeLoaderBlock() {
		return KeLoaderBlock;
	}

	public void setKeLoaderBlock(long keLoaderBlock) {
		KeLoaderBlock = keLoaderBlock;
	}

	public short getSizePcr() {
		return SizePcr;
	}

	public void setSizePcr(short sizePcr) {
		SizePcr = sizePcr;
	}

	public short getOffsetPcrSelfPcr() {
		return OffsetPcrSelfPcr;
	}

	public void setOffsetPcrSelfPcr(short offsetPcrSelfPcr) {
		OffsetPcrSelfPcr = offsetPcrSelfPcr;
	}

	public short getOffsetPcrCurrentPrcb() {
		return OffsetPcrCurrentPrcb;
	}

	public void setOffsetPcrCurrentPrcb(short offsetPcrCurrentPrcb) {
		OffsetPcrCurrentPrcb = offsetPcrCurrentPrcb;
	}

	public short getOffsetPcrContainedPrcb() {
		return OffsetPcrContainedPrcb;
	}

	public void setOffsetPcrContainedPrcb(short offsetPcrContainedPrcb) {
		OffsetPcrContainedPrcb = offsetPcrContainedPrcb;
	}

	public short getOffsetPcrInitialBStore() {
		return OffsetPcrInitialBStore;
	}

	public void setOffsetPcrInitialBStore(short offsetPcrInitialBStore) {
		OffsetPcrInitialBStore = offsetPcrInitialBStore;
	}

	public short getOffsetPcrBStoreLimit() {
		return OffsetPcrBStoreLimit;
	}

	public void setOffsetPcrBStoreLimit(short offsetPcrBStoreLimit) {
		OffsetPcrBStoreLimit = offsetPcrBStoreLimit;
	}

	public short getOffsetPcrInitialStack() {
		return OffsetPcrInitialStack;
	}

	public void setOffsetPcrInitialStack(short offsetPcrInitialStack) {
		OffsetPcrInitialStack = offsetPcrInitialStack;
	}

	public short getOffsetPcrStackLimit() {
		return OffsetPcrStackLimit;
	}

	public void setOffsetPcrStackLimit(short offsetPcrStackLimit) {
		OffsetPcrStackLimit = offsetPcrStackLimit;
	}

	public short getOffsetPrcbPcrPage() {
		return OffsetPrcbPcrPage;
	}

	public void setOffsetPrcbPcrPage(short offsetPrcbPcrPage) {
		OffsetPrcbPcrPage = offsetPrcbPcrPage;
	}

	public short getOffsetPrcbProcStateSpecialReg() {
		return OffsetPrcbProcStateSpecialReg;
	}

	public void setOffsetPrcbProcStateSpecialReg(short offsetPrcbProcStateSpecialReg) {
		OffsetPrcbProcStateSpecialReg = offsetPrcbProcStateSpecialReg;
	}

	public short getGdtR0Code() {
		return GdtR0Code;
	}

	public void setGdtR0Code(short gdtR0Code) {
		GdtR0Code = gdtR0Code;
	}

	public short getGdtR0Data() {
		return GdtR0Data;
	}

	public void setGdtR0Data(short gdtR0Data) {
		GdtR0Data = gdtR0Data;
	}

	public short getGdtR0Pcr() {
		return GdtR0Pcr;
	}

	public void setGdtR0Pcr(short gdtR0Pcr) {
		GdtR0Pcr = gdtR0Pcr;
	}

	public short getGdtR3Code() {
		return GdtR3Code;
	}

	public void setGdtR3Code(short gdtR3Code) {
		GdtR3Code = gdtR3Code;
	}

	public short getGdtR3Data() {
		return GdtR3Data;
	}

	public void setGdtR3Data(short gdtR3Data) {
		GdtR3Data = gdtR3Data;
	}

	public short getGdtR3Teb() {
		return GdtR3Teb;
	}

	public void setGdtR3Teb(short gdtR3Teb) {
		GdtR3Teb = gdtR3Teb;
	}

	public short getGdtLdt() {
		return GdtLdt;
	}

	public void setGdtLdt(short gdtLdt) {
		GdtLdt = gdtLdt;
	}

	public short getGdtTss() {
		return GdtTss;
	}

	public void setGdtTss(short gdtTss) {
		GdtTss = gdtTss;
	}

	public short getGdt64R3CmCode() {
		return Gdt64R3CmCode;
	}

	public void setGdt64R3CmCode(short gdt64r3CmCode) {
		Gdt64R3CmCode = gdt64r3CmCode;
	}

	public short getGdt64R3CmTeb() {
		return Gdt64R3CmTeb;
	}

	public void setGdt64R3CmTeb(short gdt64r3CmTeb) {
		Gdt64R3CmTeb = gdt64r3CmTeb;
	}

	public long getIopNumTriageDumpDataBlocks() {
		return IopNumTriageDumpDataBlocks;
	}

	public void setIopNumTriageDumpDataBlocks(long iopNumTriageDumpDataBlocks) {
		IopNumTriageDumpDataBlocks = iopNumTriageDumpDataBlocks;
	}

	public long getIopTriageDumpDataBlocks() {
		return IopTriageDumpDataBlocks;
	}

	public void setIopTriageDumpDataBlocks(long iopTriageDumpDataBlocks) {
		IopTriageDumpDataBlocks = iopTriageDumpDataBlocks;
	}

	public long getVfCrashDataBlock() {
		return VfCrashDataBlock;
	}

	public void setVfCrashDataBlock(long vfCrashDataBlock) {
		VfCrashDataBlock = vfCrashDataBlock;
	}

	public long getMmBadPagesDetected() {
		return MmBadPagesDetected;
	}

	public void setMmBadPagesDetected(long mmBadPagesDetected) {
		MmBadPagesDetected = mmBadPagesDetected;
	}

	public long getMmZeroedPageSingleBitErrorsDetected() {
		return MmZeroedPageSingleBitErrorsDetected;
	}

	public void setMmZeroedPageSingleBitErrorsDetected(long mmZeroedPageSingleBitErrorsDetected) {
		MmZeroedPageSingleBitErrorsDetected = mmZeroedPageSingleBitErrorsDetected;
	}

	public long getEtwpDebuggerData() {
		return EtwpDebuggerData;
	}

	public void setEtwpDebuggerData(long etwpDebuggerData) {
		EtwpDebuggerData = etwpDebuggerData;
	}

	public short getOffsetPrcbContext() {
		return OffsetPrcbContext;
	}

	public void setOffsetPrcbContext(short offsetPrcbContext) {
		OffsetPrcbContext = offsetPrcbContext;
	}

	public short getOffsetPrcbMaxBreakpoints() {
		return OffsetPrcbMaxBreakpoints;
	}

	public void setOffsetPrcbMaxBreakpoints(short offsetPrcbMaxBreakpoints) {
		OffsetPrcbMaxBreakpoints = offsetPrcbMaxBreakpoints;
	}

	public short getOffsetPrcbMaxWatchpoints() {
		return OffsetPrcbMaxWatchpoints;
	}

	public void setOffsetPrcbMaxWatchpoints(short offsetPrcbMaxWatchpoints) {
		OffsetPrcbMaxWatchpoints = offsetPrcbMaxWatchpoints;
	}

	public int getOffsetKThreadStackLimit() {
		return OffsetKThreadStackLimit;
	}

	public void setOffsetKThreadStackLimit(int offsetKThreadStackLimit) {
		OffsetKThreadStackLimit = offsetKThreadStackLimit;
	}

	public int getOffsetKThreadStackBase() {
		return OffsetKThreadStackBase;
	}

	public void setOffsetKThreadStackBase(int offsetKThreadStackBase) {
		OffsetKThreadStackBase = offsetKThreadStackBase;
	}

	public int getOffsetKThreadQueueListEntry() {
		return OffsetKThreadQueueListEntry;
	}

	public void setOffsetKThreadQueueListEntry(int offsetKThreadQueueListEntry) {
		OffsetKThreadQueueListEntry = offsetKThreadQueueListEntry;
	}

	public int getOffsetEThreadIrpList() {
		return OffsetEThreadIrpList;
	}

	public void setOffsetEThreadIrpList(int offsetEThreadIrpList) {
		OffsetEThreadIrpList = offsetEThreadIrpList;
	}

	public short getOffsetPrcbIdleThread() {
		return OffsetPrcbIdleThread;
	}

	public void setOffsetPrcbIdleThread(short offsetPrcbIdleThread) {
		OffsetPrcbIdleThread = offsetPrcbIdleThread;
	}

	public short getOffsetPrcbNormalDpcState() {
		return OffsetPrcbNormalDpcState;
	}

	public void setOffsetPrcbNormalDpcState(short offsetPrcbNormalDpcState) {
		OffsetPrcbNormalDpcState = offsetPrcbNormalDpcState;
	}

	public short getOffsetPrcbDpcStack() {
		return OffsetPrcbDpcStack;
	}

	public void setOffsetPrcbDpcStack(short offsetPrcbDpcStack) {
		OffsetPrcbDpcStack = offsetPrcbDpcStack;
	}

	public short getOffsetPrcbIsrStack() {
		return OffsetPrcbIsrStack;
	}

	public void setOffsetPrcbIsrStack(short offsetPrcbIsrStack) {
		OffsetPrcbIsrStack = offsetPrcbIsrStack;
	}

	public short getSizeKDPC_STACK_FRAME() {
		return SizeKDPC_STACK_FRAME;
	}

	public void setSizeKDPC_STACK_FRAME(short sizeKDPC_STACK_FRAME) {
		SizeKDPC_STACK_FRAME = sizeKDPC_STACK_FRAME;
	}

	public short getOffsetKPriQueueThreadListHead() {
		return OffsetKPriQueueThreadListHead;
	}

	public void setOffsetKPriQueueThreadListHead(short offsetKPriQueueThreadListHead) {
		OffsetKPriQueueThreadListHead = offsetKPriQueueThreadListHead;
	}

	public short getOffsetKThreadWaitReason() {
		return OffsetKThreadWaitReason;
	}

	public void setOffsetKThreadWaitReason(short offsetKThreadWaitReason) {
		OffsetKThreadWaitReason = offsetKThreadWaitReason;
	}

	public short getPadding1() {
		return Padding1;
	}

	public void setPadding1(short padding1) {
		Padding1 = padding1;
	}

	public long getPteBase() {
		return PteBase;
	}

	public void setPteBase(long pteBase) {
		PteBase = pteBase;
	}

	public long getRetpolineStubFunctionTable() {
		return RetpolineStubFunctionTable;
	}

	public void setRetpolineStubFunctionTable(long retpolineStubFunctionTable) {
		RetpolineStubFunctionTable = retpolineStubFunctionTable;
	}

	public int getRetpolineStubFunctionTableSize() {
		return RetpolineStubFunctionTableSize;
	}

	public void setRetpolineStubFunctionTableSize(int retpolineStubFunctionTableSize) {
		RetpolineStubFunctionTableSize = retpolineStubFunctionTableSize;
	}

	public int getRetpolineStubOffset() {
		return RetpolineStubOffset;
	}

	public void setRetpolineStubOffset(int retpolineStubOffset) {
		RetpolineStubOffset = retpolineStubOffset;
	}

	public int getRetpolineStubSize() {
		return RetpolineStubSize;
	}

	public void setRetpolineStubSize(int retpolineStubSize) {
		RetpolineStubSize = retpolineStubSize;
	}

	public short getOffsetEProcessMmHotPatchContext() {
		return OffsetEProcessMmHotPatchContext;
	}

	public void setOffsetEProcessMmHotPatchContext(short offsetEProcessMmHotPatchContext) {
		OffsetEProcessMmHotPatchContext = offsetEProcessMmHotPatchContext;
	}

}
