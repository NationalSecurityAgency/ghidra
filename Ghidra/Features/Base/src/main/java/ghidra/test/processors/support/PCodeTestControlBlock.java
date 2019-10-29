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
package ghidra.test.processors.support;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.*;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;

/**
 * <code>PCodeTestControlBlock</code> data is read from each binary test file and
 * identified by the MAIN_CONTROL_BLOCK_MAGIC 64-bit character field value at the start of the 
 * data structure.  Only one instance of this should exist within the binary.
 */
public class PCodeTestControlBlock extends PCodeTestAbstractControlBlock {

	static final String INITIAL_FUNCTION_NAME = "<NONE>";
	static final String UNKNOWN_FUNCTION_NAME = "<UNKNOWN>";

	private static final String MAIN_CONTROL_BLOCK_MAGIC = "AbCdEFgH";

	private static Structure testInfoStruct; // TestInfo structure
	private static Structure groupInfoStruct; // GroupInfo structure

	private final AddressSetView restrictedSet;

	public final PCodeTestFile testFile;
	public final String cachedProgramPath;

	private List<PCodeTestGroup> testGroups; // test group data

	// TestInfo data read from program memory
	private Address onPassFunctionAddress;
	private Address onErrorFunctionAddress;
	private Address onDoneFunctionAddress;
	private Address sprintfFunctionAddress;
	private Address sprintfBufferAddress;

	// TestInfo structure offsets for runtime use
	private int numPassOffset;
	private int numFailOffset;
	private int lastTestPosOffset;
	private int lastErrorLineOffset;
	private int lastErrorFileOffset;
	private int lastFuncOffset;

	private int sprintfEnableOffset;

	private final PCodeTestResults testResults;

	/**
	 * Construct test control block instance for the specified
	 * program.  Create TestInfo structure data within program if requested.
	 * @param program program containing control block structure
	 * @param restrictedSet the restricted memory area which should be searched 
	 * for control structures
	 * @param testInfoStructAddr address of Main TestInfo structure
	 * @param testFile original binary test file 
	 * @param cachedProgramPath program path within program file cache
	 * @param applyStruct create structure Data within program if true
	 * @throws InvalidControlBlockException
	 * @throws CodeUnitInsertionException if applyStruct failed
	 */
	private PCodeTestControlBlock(Program program, AddressSetView restrictedSet,
			Address testInfoStructAddr, PCodeTestFile testFile, String cachedProgramPath,
			boolean applyStruct, PCodeTestResults testResults)
			throws InvalidControlBlockException, CodeUnitInsertionException {
		super(program, testInfoStructAddr, testInfoStruct);

		this.restrictedSet = restrictedSet;
		this.testFile = testFile;
		this.cachedProgramPath = cachedProgramPath;
		this.testResults = testResults;

		readControlBlock(applyStruct);

		numPassOffset = getStructureComponent(infoProgramStruct, "numpass");
		numFailOffset = getStructureComponent(infoProgramStruct, "numfail");
		lastTestPosOffset = getStructureComponent(infoProgramStruct, "lastTestPos");
		lastErrorLineOffset = getStructureComponent(infoProgramStruct, "lastErrorLine");
		lastErrorFileOffset = getStructureComponent(infoProgramStruct, "lastErrorFile");
		lastFuncOffset = getStructureComponent(infoProgramStruct, "lastFunc");

		sprintfEnableOffset = getStructureComponent(infoProgramStruct, "sprintf5Enabled");
	}

	/**
	 * Find Main TestInfo structure within memory and return instance of PCodeTestControlBlock
	 * @param program
	 * @param testFile original binary test file
	 * @param restrictedSet a restricted set to be searched for control structures
	 * @param cachedProgramPath program path within program file cache
	 * @param testInfoStruct TestInfo structure definition
	 * @param groupInfoStruct GroupInfo structure definition
	 * @param applyStruct create structure Data within program if true
	 * @param testResults test results storage object
	 * @return instance of PCodeTestControlBlock
	 * @throws InvalidControlBlockException
	 * @throws CodeUnitInsertionException
	 */
	static PCodeTestControlBlock getMainControlBlock(Program program, PCodeTestFile testFile,
			AddressSetView restrictedSet, String cachedProgramPath, Structure testInfoStruct,
			Structure groupInfoStruct, boolean applyStruct, PCodeTestResults testResults)
			throws InvalidControlBlockException, CodeUnitInsertionException {

		PCodeTestControlBlock.testInfoStruct = testInfoStruct;
		PCodeTestControlBlock.groupInfoStruct = groupInfoStruct;

		Memory memory = program.getMemory();
		byte[] magicBytes = getCharArrayBytes(program, MAIN_CONTROL_BLOCK_MAGIC);

		Address startOfControlBlock = findBytes(memory, restrictedSet, magicBytes);
		if (startOfControlBlock == null) {
			throw new InvalidControlBlockException("TestInfo structure not found");
		}

		return new PCodeTestControlBlock(program, restrictedSet, startOfControlBlock, testFile,
			cachedProgramPath, applyStruct, testResults);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + ":" + testFile;
	}

	public List<PCodeTestGroup> getTestGroups() {
		return testGroups;
	}

	public Address getBreakOnDoneAddress() {
		return onDoneFunctionAddress;
	}

	public Address getBreakOnPassAddress() {
		return onPassFunctionAddress;
	}

	public Address getBreakOnErrorAddress() {
		return onErrorFunctionAddress;
	}

	public Address getSprintf5Address() {
		return sprintfFunctionAddress;
	}

	public Address getPrintfBufferAddress() {
		return sprintfBufferAddress;
	}

	public PCodeTestResults getTestResults() {
		return testResults;
	}

	@Override
	protected void readControlBlock(boolean applyStruct)
			throws InvalidControlBlockException, CodeUnitInsertionException {

		super.readControlBlock(applyStruct);

		int ptrSzOffset = getStructureComponent(infoProgramStruct, "ptrSz");
		int byteOrderOffset = getStructureComponent(infoProgramStruct, "byteOrder");
		int onPassPtrOffset = getStructureComponent(infoProgramStruct, "onPass");
		int onErrorPtrOffset = getStructureComponent(infoProgramStruct, "onError");
		int onDonePtrOffset = getStructureComponent(infoProgramStruct, "onDone");

		int sprintfPtrOffset = getStructureComponent(infoProgramStruct, "sprintf5");
		int sprintfBufferPtrOffset = getStructureComponent(infoProgramStruct, "sprintf5buffer");

		if (applyStruct) {
			forceCodePointer(infoStructAddr.add(onPassPtrOffset));
			forceCodePointer(infoStructAddr.add(onErrorPtrOffset));
			forceCodePointer(infoStructAddr.add(onDonePtrOffset));
			forceCodePointer(infoStructAddr.add(sprintfBufferPtrOffset));
		}

		DumbMemBufferImpl memBuffer = new DumbMemBufferImpl(program.getMemory(), infoStructAddr);
		try {

			// Check byte-order
			int byteOrder = memBuffer.getInt(byteOrderOffset);
			if (byteOrder != 0x1020304) {
				throw new InvalidControlBlockException(
					"TestInfo @ " + infoStructAddr.toString(true) +
						" has invalid byteOrder - language endianess may be incorrect (" +
						Integer.toHexString(byteOrder) + ")");
			}

			// Check pointer size
			// Must adjust size recorded by compiler
			int ptrSize = memBuffer.getInt(ptrSzOffset);
			DataOrganization dataOrganization = program.getDataTypeManager().getDataOrganization();
			ptrSize *= dataOrganization.getCharSize();
			if (ptrSize < 2 || ptrSize > 8) {
				throw new InvalidControlBlockException("TestInfo @ " +
					infoStructAddr.toString(true) + " has unsupported pointer size: " + ptrSize);
			}
			if (ptrSize != pointerSize) {
				String id =
					program.getLanguageID() + ":" + program.getCompilerSpec().getCompilerSpecID();
				Msg.warn(this, "TestInfo @ " + infoStructAddr.toString(true) + " ptrSz=" + ptrSize +
					" differs from data-organization size of " + pointerSize + " (" + id + ")");
			}

			// get onPass function pointer		
			onPassFunctionAddress = readCodePointer(memBuffer, onPassPtrOffset, applyStruct);

			// get onError function pointer		
			onErrorFunctionAddress = readCodePointer(memBuffer, onErrorPtrOffset, applyStruct);

			// get onDone function pointer		
			onDoneFunctionAddress = readCodePointer(memBuffer, onDonePtrOffset, applyStruct);

			// get sprintf function pointer		
			sprintfFunctionAddress = readCodePointer(memBuffer, sprintfPtrOffset, applyStruct);

			// get sprintf buffer pointer		
			sprintfBufferAddress = readCodePointer(memBuffer, sprintfBufferPtrOffset, applyStruct);

		}
		catch (MemoryAccessException e) {
			throw new InvalidControlBlockException("TestInfo program read error", e);
		}

		// Find all test groups by locating corresponding TestInfo structure	
		findTestGroups(applyStruct);

	}

	private void findTestGroups(boolean applyStruct)
			throws InvalidControlBlockException, CodeUnitInsertionException {

		Memory memory = program.getMemory();

		byte[] groupStructMagicBytes =
			getCharArrayBytes(program, PCodeTestGroupControlBlock.GROUP_CONTROL_BLOCK_MAGIC);

		testGroups = new ArrayList<>();

		AddressSet set = new AddressSet(restrictedSet);
		while (true) {

			Address startOfControlBlock = findBytes(memory, set, groupStructMagicBytes);
			if (startOfControlBlock == null) {
				break;
			}

			PCodeTestGroupControlBlock controlBlock = new PCodeTestGroupControlBlock(program,
				startOfControlBlock, groupInfoStruct, applyStruct, this);
			PCodeTestGroup testGroup = new PCodeTestGroup(controlBlock);
			testGroups.add(testGroup);

			// Remove previously searched addresses from search address set
			Address endAddr = startOfControlBlock.add(groupInfoStruct.getLength()).previous();
			AddressRange nextRange = set.getFirstRange();
			while (nextRange != null && !nextRange.contains(endAddr)) {
				set.delete(nextRange);
				nextRange = set.getFirstRange();
			}
			if (set.contains(endAddr)) {
				set = set.subtract(new AddressSet(set.getMinAddress(),
					startOfControlBlock.add(groupInfoStruct.getLength()).previous()));
			}
		}

		if (testGroups.size() == 0) {
			throw new InvalidControlBlockException(
				"P-Code test binary does not define any test groups");
		}

	}

	/**
	 * Enable/Diable sprintf use within P-Code test emulation.
	 * @param emuTestRunner emulator test runner
	 * @param enable sprintf enablement
	 */
	void setSprintfEnabled(EmulatorTestRunner emuTestRunner, boolean enable) {
		Address addr =
			getMirroredDataAddress(emuTestRunner, infoStructAddr.add(sprintfEnableOffset));
		emuWrite(emuTestRunner.getEmulatorHelper(), addr, SIZEOF_U4, enable ? 1 : 0);
	}

	/**
	 * Get 'numpass' field value from emulation memory state
	 * @param emuTestRunner emulator test runner
	 * @return 'numpass' field value
	 */
	int getNumberPassed(EmulatorTestRunner emuTestRunner) {
		Address addr = getMirroredDataAddress(emuTestRunner, infoStructAddr.add(numPassOffset));
		return (int) emuRead(emuTestRunner.getEmulatorHelper(), addr, SIZEOF_U4);
	}

	/**
	 * Set 'numpass' field value within emulation memory state
	 * @param emuTestRunner emulator test runner
	 * @param value field value
	 */
	void setNumberPassed(EmulatorTestRunner emuTestRunner, int value) {
		Address addr = getMirroredDataAddress(emuTestRunner, infoStructAddr.add(numPassOffset));
		emuWrite(emuTestRunner.getEmulatorHelper(), addr, SIZEOF_U4, value);
	}

	/**
	 * Get 'numfail' field value from emulation memory state
	 * @param emuTestRunner emulator test runner
	 * @return 'numfail' field value
	 */
	int getNumberFailed(EmulatorTestRunner emuTestRunner) {
		Address addr = getMirroredDataAddress(emuTestRunner, infoStructAddr.add(numFailOffset));
		return (int) emuRead(emuTestRunner.getEmulatorHelper(), addr, SIZEOF_U4);
	}

	/**
	 * Set 'numfail' field value within emulation memory state
	 * @param emuTestRunner emulator test runner
	 * @param value field value
	 */
	void setNumberFailed(EmulatorTestRunner emuTestRunner, int value) {
		Address addr = getMirroredDataAddress(emuTestRunner, infoStructAddr.add(numFailOffset));
		emuWrite(emuTestRunner.getEmulatorHelper(), addr, SIZEOF_U4, value);
	}

	/**
	 * Get 'lastTestPos' field value from emulation memory state
	 * @param emuTestRunner emulator test runner
	 * @return 'lastTestPos' field value
	 */
	int getLastTestIndex(EmulatorTestRunner emuTestRunner) {
		Address addr = getMirroredDataAddress(emuTestRunner, infoStructAddr.add(lastTestPosOffset));
		return (int) emuRead(emuTestRunner.getEmulatorHelper(), addr, SIZEOF_U4);
	}

	/**
	 * Get 'lastErrorLine' field value from emulation memory state
	 * @param emuTestRunner emulator test runner
	 * @return 'lastErrorLine' field value
	 */
	int getLastErrorLine(EmulatorTestRunner emuTestRunner) {
		Address addr =
			getMirroredDataAddress(emuTestRunner, infoStructAddr.add(lastErrorLineOffset));
		return (int) emuRead(emuTestRunner.getEmulatorHelper(), addr, SIZEOF_U4);
	}

	/**
	 * Get 'lastErrorFile' string value from emulation memory state.  Must follow string
	 * pointer contained within lastErrorFile field.
	 * @param emuTestRunner emulator test runner
	 * @return 'lastErrorLine' field value
	 */
	String getLastErrorFile(EmulatorTestRunner emuTestRunner) {
		Address addr =
			getMirroredDataAddress(emuTestRunner, infoStructAddr.add(lastErrorFileOffset));
		long fileNameOffset = emuRead(emuTestRunner.getEmulatorHelper(), addr, pointerSize);
		addr = addr.getNewAddress(fileNameOffset, true);
		addr = getMirroredDataAddress(emuTestRunner, addr);
		return emuReadString(emuTestRunner.getEmulatorHelper(), addr);
	}

	/**
	 * Get the name of the last test function to be run
	 * @param emuTestRunner
	 * @return last test function name
	 */
	String getLastFunctionName(EmulatorTestRunner emuTestRunner, TestLogger logger,
			PCodeTestGroup activeGroup) {
		Address ptrStorageAddr = infoStructAddr.add(lastFuncOffset);
		Address ptrAddr = getMirroredDataAddress(emuTestRunner, ptrStorageAddr);
		long funcNameOffset = emuRead(emuTestRunner.getEmulatorHelper(), ptrAddr, pointerSize);
		Address strAddr = ptrAddr.getNewAddress(funcNameOffset, true);
		strAddr = getMirroredDataAddress(emuTestRunner, strAddr);
		String fnName = emuReadString(emuTestRunner.getEmulatorHelper(), strAddr);
		if ("none".equals(fnName)) {
			if (logger != null) {
				logger.log(activeGroup, "ERROR last executed function name pointer stored at " +
					ptrStorageAddr + " has not been set (reported as <NONE>)");
			}
			return INITIAL_FUNCTION_NAME;
		}
		String altName = null;
		if (!fnName.endsWith(PCodeTestGroupControlBlock.TEST_GROUP_FUNCTION_SUFFIX)) {
			altName = fnName + PCodeTestGroupControlBlock.TEST_GROUP_FUNCTION_SUFFIX;
		}
		if (activeGroup != null) {
			if (activeGroup.controlBlock.getFunctionInfo(fnName) != null) {
				return fnName;
			}
			if (altName != null && activeGroup.controlBlock.getFunctionInfo(altName) != null) {
				return fnName;
			}
		}
		if (logger != null) {
			logger.log(activeGroup,
				"ERROR last executed function name pointer stored at " + ptrStorageAddr +
					" was improperly set (reported as <UNKNOWN>, pointer=" + strAddr + ")");
		}
		return UNKNOWN_FUNCTION_NAME;
	}

}
