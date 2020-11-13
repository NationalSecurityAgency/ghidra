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
package ghidra.app.emulator;

import java.util.*;

import ghidra.app.emulator.memory.*;
import ghidra.app.emulator.state.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.*;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Emulator {

	private final MemoryFaultHandler faultHandler;

	private SleighLanguage language;
	private AddressFactory addrFactory;

	private CompositeLoadImage loadImage = new CompositeLoadImage();

	private RegisterState mstate;
	private MemoryPageBank registerState;
	private FilteredMemoryState memState;
	private ghidra.pcode.emulate.BreakTableCallBack breakTable;
	private Emulate emulator;

	private boolean emuHalt = true;
	private boolean isExecuting = false;

	private boolean writeBack = false;
	private int pageSize;				// The preferred page size for a paged memory state

	private String pcName;
	private long initialPC;
	private int instExecuted = 0;

	public Emulator(EmulatorConfiguration cfg) {

		this.faultHandler = cfg.getMemoryFaultHandler();

		pcName = cfg.getProgramCounterName();
		writeBack = cfg.isWriteBackEnabled();
		pageSize = cfg.getPreferredMemoryPageSize();

		Language lang = cfg.getLanguage();
		if (!(lang instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Invalid configuartion language [" +
				lang.getLanguageID() + "]: only Sleigh languages are supported by emulator");
		}

		// TODO: The way this is currently done, we are unable to emulate within overlay spaces
		// The addrFactory should be obtained memState which is a reversal
		// When a program load image is used the addrFactory should come from the program and
		// not the language.  Things may also get complex in terms of handling loads/stores and
		// flow associated with overlays.

		language = (SleighLanguage) lang;
		addrFactory = lang.getAddressFactory();

		EmulatorLoadData load = cfg.getLoadData();
		loadImage.addProvider(load.getMemoryLoadImage(), load.getView());
		mstate = load.getInitialRegisterState();

		initMemState(mstate);

		breakTable = new BreakTableCallBack(language);
		emulator = new Emulate(language, memState, breakTable);

		try {
			setExecuteAddress(initialPC);
		}
		catch (LowlevelError lle) {
			Msg.warn(this, "pc is unmappable -- no execution possible");
		}
	}

	/**
	 * Get the page size to use with a specific AddressSpace. The page containers (MemoryBank)
	 * assume page size is always power of 2. Any address space is assigned at least 8-bits of
	 * addressable locations, so at the very least, the size is divisible by 256. Starting with this
	 * minimum, this method finds the power of 2 that is closest to the preferred page size (pageSize)
	 * but that still divides the size of the space.
	 * @param space is the specific AddressSpace
	 * @return the page size to use
	 */
	private int getValidPageSize(AddressSpace space) {
		int ps = 256;	// Minimum page size supported
		long spaceSize = space.getMaxAddress().getOffset() + 1;	// Number of bytes in the space (0 if 2^64 bytes)
		if ((spaceSize & 0xff) != 0) {
			Msg.warn(this, "Emulator using page size of 256 bytes for " + space.getName() +
				" which is NOT a multiple of 256");
			return ps;
		}
		spaceSize >>>= 8;	// Divide required size by 256 (evenly)
		while (ps < pageSize) {	// If current page size is smaller than preferred page size
			if ((spaceSize & 1) != 0) {
				break;			// a bigger page size does not divide the space size evenly, so use current size
			}
			ps <<= 1;	// Bump up current page size to next power of 2
			spaceSize >>>= 1;	// Divide (evenly) by 2
		}

		return ps;
	}

	private void initMemState(RegisterState rstate) {

		memState = new FilteredMemoryState(language);

		for (AddressSpace space : addrFactory.getPhysicalSpaces()) {
			if (!space.isLoadedMemorySpace()) {
				continue;
			}
			FilteredMemoryPageOverlay ramBank = getMemoryBank(space, getValidPageSize(space));
			memState.setMemoryBank(ramBank);
		}

		AddressSpace registerSpace = addrFactory.getRegisterSpace();
		registerState = new FilteredRegisterBank(registerSpace, pageSize, rstate, language,
			writeBack, faultHandler);

		memState.setMemoryBank(registerState);

		initRegisters(false);
	}

	public MemoryState cloneMemory() {
		MemoryState newMemState = new FilteredMemoryState(language);

		for (AddressSpace space : addrFactory.getPhysicalSpaces()) {
			if (!space.isLoadedMemorySpace()) {
				continue;
			}
			FilteredMemoryPageOverlay ramBank = getMemoryBank(space, getValidPageSize(space));
			newMemState.setMemoryBank(ramBank);
		}
		return newMemState;
	}

	public FilteredMemoryPageOverlay getMemoryBank(AddressSpace space, int ps) {
		MemoryImage image =
			new MemoryImage(space, language.isBigEndian(), ps, loadImage, faultHandler);
		return new FilteredMemoryPageOverlay(space, image, writeBack);
	}

	/**
	 * Initialize memory state using the initial register state.  If restore is true,
	 * only those registers within the register space which have been modified will
	 * be reported and restored to their initial state.
	 * @param restore if true restore modified registers within the register space only
	 */
	private void initRegisters(boolean restore) {
		DataConverter conv = DataConverter.getInstance(language.isBigEndian());
		Set<String> keys = mstate.getKeys();
		for (String key : keys) {
			List<byte[]> vals = mstate.getVals(key);
			List<Boolean> initiailizedVals = mstate.isInitialized(key);
			for (int i = 0; i < vals.size(); i++) {
				String useKey = "";
				if (key.equals("GDTR") || key.equals("IDTR") || key.equals("LDTR")) {
					if (i == 0) {
						useKey = key + "_Limit";
					}
					if (i == 1) {
						useKey = key + "_Address";
					}
				}
				else if (key.equals("S.base")) {
					Integer lval = conv.getInt(vals.get(i));
					if (lval != 0 && i < vals.size() - 1) {
						useKey = "FS_OFFSET"; // Colossal hack
						memState.setValue("FS", (i + 2) * 0x8);
					}
				}
				else {
					useKey = (vals.size() > 1) ? key + i : key;
				}
				Register register = language.getRegister(useKey);
				if (register == null) {
					useKey = useKey.toUpperCase();
					register = language.getRegister(useKey);
				}
				if (register != null) {
					if (restore && !register.getAddress().isRegisterAddress()) {
						continue; // only restore registers within register space
					}
					byte[] valBytes = vals.get(i);
					boolean initializedValue = initiailizedVals.get(i);

					Address regAddr = register.getAddress();

					if (restore) {
						byte[] curVal = new byte[valBytes.length];
						memState.getChunk(curVal, regAddr.getAddressSpace(), regAddr.getOffset(),
							register.getMinimumByteSize(), false);
						if (Arrays.equals(curVal, valBytes)) {
							continue;
						}
						System.out.println(
							"resetRegisters : " + useKey + "=" + dumpBytesAsSingleValue(valBytes) +
								"->" + dumpBytesAsSingleValue(curVal));
					}

					memState.setChunk(valBytes, regAddr.getAddressSpace(), regAddr.getOffset(),
						register.getMinimumByteSize());

					if (!initializedValue) {
						memState.setInitialized(false, regAddr.getAddressSpace(),
							regAddr.getOffset(), register.getMinimumByteSize());
					}

					if (register.isProgramCounter() ||
						register.getName().equalsIgnoreCase(pcName)) {
						initialPC = conv.getValue(valBytes, valBytes.length);
					}
				}
			}
		}
	}

	private String dumpBytesAsSingleValue(byte[] bytes) {
		StringBuffer buf = new StringBuffer("0x");
		if (language.isBigEndian()) {
			for (byte b : bytes) {
				String byteStr = Integer.toHexString(b & 0xff);
				if (byteStr.length() == 1) {
					buf.append('0');
				}
				buf.append(byteStr);
			}
		}
		else {
			for (int i = bytes.length - 1; i >= 0; i--) {
				String byteStr = Integer.toHexString(bytes[i] & 0xff);
				if (byteStr.length() == 1) {
					buf.append('0');
				}
				buf.append(byteStr);
			}
		}
		return buf.toString();
	}

	public void dispose() {
		emuHalt = true;
		emulator.dispose();
		if (writeBack) {
			initRegisters(true);
			mstate.dispose();
		}
		loadImage.dispose();
	}

	public Address genAddress(String addr) {
		return addrFactory.getDefaultAddressSpace().getAddress(NumericUtilities.parseHexLong(addr));
	}

	public long getPC() {
		return memState.getValue(pcName);
	}

	public String getPCRegisterName() {
		return pcName;
	}

	public MemoryState getMemState() {
		return memState;
	}

	public FilteredMemoryState getFilteredMemState() {
		return memState;
	}

	public void addMemoryAccessFilter(MemoryAccessFilter filter) {
		filter.addFilter(this);
	}

	public BreakTableCallBack getBreakTable() {
		return breakTable;
	}

	public void setExecuteAddress(long addressableWordOffset) {
		AddressSpace space = addrFactory.getDefaultAddressSpace();
		Address address = space.getTruncatedAddress(addressableWordOffset, true);
		emulator.setExecuteAddress(address);
	}

	public Address getExecuteAddress() {
		return emulator.getExecuteAddress();
	}

	public Address getLastExecuteAddress() {
		return emulator.getLastExecuteAddress();
	}

	public Set<String> getDefaultContext() {
		return mstate.getKeys();
	}

	public void setHalt(boolean halt) {
		emuHalt = halt;
	}

	public boolean getHalt() {
		return emuHalt;
	}

	public void executeInstruction(boolean stopAtBreakpoint, TaskMonitor monitor)
			throws CancelledException, LowlevelError, InstructionDecodeException {
		isExecuting = true;
		try {
			emulator.executeInstruction(stopAtBreakpoint, monitor);
			instExecuted++;
		}
		finally {
			isExecuting = false;
		}
	}

	/**
	 * @return true if halted at a breakpoint
	 */
	public boolean isAtBreakpoint() {
		return getHalt() && emulator.getExecutionState() == EmulateExecutionState.BREAKPOINT;
	}

	/**
	 * @return emulator execution state.  This can be useful within a memory fault handler to
	 * determine if a memory read was associated with instruction parsing (i.e., PCODE_EMIT) or
	 * normal an actual emulated read (i.e., EXECUTE).
	 */
	public EmulateExecutionState getEmulateExecutionState() {
		return emulator.getExecutionState();
	}

	/**
	 * @return true if emulator is busy executing an instruction
	 */
	public boolean isExecuting() {
		return isExecuting;
	}

	public SleighLanguage getLanguage() {
		return language;
	}

	/**
	 * Disassemble from the current execute address
	 * @param count number of contiguous instructions to disassemble
	 * @return list of instructions
	 */
	public List<String> disassemble(Integer count) {
		if (!emuHalt || isExecuting) {
			throw new IllegalStateException("disassembly not allowed while emulator is executing");
		}

		// TODO: This can provide bad disassembly if reliant on future context state (e.g., end of loop)

		List<String> disassembly = new ArrayList<>();

		EmulateDisassemblerContext disassemblerContext = emulator.getNewDisassemblerContext();
		Address addr = getExecuteAddress();
		EmulateMemoryStateBuffer memBuffer = new EmulateMemoryStateBuffer(memState, addr);

		Disassembler disassembler = Disassembler.getDisassembler(language, addrFactory,
			TaskMonitor.DUMMY, null);

		boolean stopOnError = false;

		while (count > 0 && !stopOnError) {
			memBuffer.setAddress(addr);
			disassemblerContext.setCurrentAddress(addr);

			InstructionBlock block = disassembler.pseudoDisassembleBlock(memBuffer,
				disassemblerContext.getCurrentContextRegisterValue(), count);

			if (block.hasInstructionError() && count > block.getInstructionCount()) {
				InstructionError instructionError = block.getInstructionConflict();
				Msg.error(this,
					"Target disassembler error at " + instructionError.getConflictAddress() + ": " +
						instructionError.getConflictMessage());
				stopOnError = true;
			}

			Instruction lastInstr = null;
			Iterator<Instruction> iterator = block.iterator();
			while (iterator.hasNext() && count != 0) {
				Instruction instr = iterator.next();
				disassembly.add(instr.getAddressString(false, true) + " " + instr.toString());
				lastInstr = instr;
				--count;
			}

			try {
				addr = lastInstr.getAddress().addNoWrap(lastInstr.getLength());
			}
			catch (Exception e) {
				count = 0;
			}
		}

		return disassembly;
	}

	public int getTickCount() {
		return instExecuted;
	}

	/**
	 * Returns the current context register value.  The context value returned reflects
	 * its state when the previously executed instruction was 
	 * parsed/executed.  The context value returned will feed into the next 
	 * instruction to be parsed with its non-flowing bits cleared and
	 * any future context state merged in.
	 * @return context as a RegisterValue object
	 */
	public RegisterValue getContextRegisterValue() {
		return emulator.getContextRegisterValue();
	}

	/**
	 * Sets the context register value at the current execute address.
	 * The Emulator should not be running when this method is invoked.
	 * Only flowing context bits should be set, as non-flowing bits
	 * will be cleared prior to parsing on instruction.  In addition,
	 * any future context state set by the pcode emitter will
	 * take precedence over context set using this method.  This method
	 * is primarily intended to be used to establish the initial 
	 * context state.
	 * @param regValue is the value to set context to
	 */
	public void setContextRegisterValue(RegisterValue regValue) {
		emulator.setContextRegisterValue(regValue);
	}

	/**
	 * Add memory load image provider
	 * @param provider memory load image provider
	 * @param view memory region which corresponds to provider
	 */
	public void addProvider(MemoryLoadImage provider, AddressSetView view) {
		loadImage.addProvider(provider, view);
	}

}
