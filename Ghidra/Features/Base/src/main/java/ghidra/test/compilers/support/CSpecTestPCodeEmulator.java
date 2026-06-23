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
package ghidra.test.compilers.support;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.function.Consumer;

import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.util.Msg;

/**
 * An extension of {@link PcodeEmulator} that can load program memory and set up the emulator 
 * to run at a specific function entry point.
 */
public class CSpecTestPCodeEmulator extends PcodeEmulator {
	private boolean traceDisabled = true;
	private int traceLevel = 3;
	private Consumer<String> logger = (msg -> Msg.debug(this, msg));

	public CSpecTestPCodeEmulator(Language lang) {
		super(lang);
	}

	public CSpecTestPCodeEmulator(Language lang, boolean traceDisabled, int traceLevel) {
		this(lang, traceDisabled, traceLevel, null);
	}

	public CSpecTestPCodeEmulator(Language lang, boolean traceDisabled, int traceLevel,
			Consumer<String> logger) {
		super(lang);
		this.traceDisabled = traceDisabled;
		this.traceLevel = traceLevel;
		if (logger != null)
			this.logger = logger;
	}

	/**
	 * Create BytesPcodeThread object with an overwritten 'createInstructionDecoder' method.
	 * @param name The name of the thread.
	 */
	@Override
	protected BytesPcodeThread createThread(String name) {
		return new BytesPcodeThread(name, this) {
			@Override
			protected SleighInstructionDecoder createInstructionDecoder(
					PcodeExecutorState<byte[]> sharedState) {
				return new SleighInstructionDecoder(language, sharedState) {
					@Override
					public PseudoInstruction decodeInstruction(Address address,
							RegisterValue context) {
						//Msg.debug(this, "Dissassembly at " + address + ": ");
						PseudoInstruction inst = super.decodeInstruction(address, context);
						//Msg.debug(this, inst.toString());

						if (!traceDisabled && traceLevel > 0) {
							logger.accept(
								"Disassembly at " + address + ": " + inst.toString());
						}

						return inst;
					}
				};
			}
		};
	}

	/**
	 * Load the function entry point context registers into emulator, create stack space,
	 * set program counter. Return a emulator thread ready for a run() call 
	 * @param func The function to prepare the emulator to run.
	 * @return {@code PcodeThread<byte[]>}
	 */
	public PcodeThread<byte[]> prepareFunction(Function func) {
		PcodeThread<byte[]> emuThread = newThread();
		PcodeArithmetic<byte[]> emuArith = emuThread.getArithmetic();

		long stackOffset =
			(func.getEntryPoint().getAddressSpace().getMaxAddress().getOffset() >>> 1) - 0x7ff;
		Register stackReg = func.getProgram().getCompilerSpec().getStackPointer();

		emuThread.getState()
				.setVar(stackReg,
					emuArith.fromConst(stackOffset, stackReg.getMinimumByteSize()));

		Instruction entry =
			func.getProgram().getListing().getInstructionAt(func.getEntryPoint());

		for (Register reg : entry.getRegisters()) {
			RegisterValue val = entry.getRegisterValue(reg);
			if (reg.isBaseRegister() && val != null && val.hasAnyValue()) {
				//Msg.debug(this, "Adding register: " + reg + ", is BE? " + reg.isBigEndian() +
				//	", is context? " + reg.isProcessorContext());
				byte[] curVal = emuThread.getState().getVar(reg, Reason.INSPECT);
				byte[] bytes = val.toBytes();
				// bytes field of a RegisterValue is (mask : val) concatenated
				byte[] maskedVal = new byte[bytes.length / 2];
				for (int i = 0; i < maskedVal.length; i++) {
					// don't adjust endianness for context registers
					if (!reg.isBigEndian() && !reg.isProcessorContext()) {
						maskedVal[maskedVal.length - 1 - i] =
							(byte) (bytes[i] & bytes[i + maskedVal.length]);
					}
					else {
						maskedVal[i] = (byte) (bytes[i] & bytes[i + maskedVal.length]);
					}
				}
				emuThread.getState().setVar(reg, emuArith.fromConst(maskedVal));

				if (!traceDisabled && traceLevel > 1) {
					logger.accept("Adding register: " + reg + ", is BE? " + reg.isBigEndian() +
						", is context? " + reg.isProcessorContext());
					logger.accept("\tRegister " + reg + " set to value: [" +
						HexFormat.ofDelimiter(", ").formatHex(maskedVal) + "]");
					logger.accept(
						"\tFrom context (mask : value): [" +
							HexFormat.ofDelimiter(", ")
									.formatHex(Arrays.copyOfRange(bytes, 0, curVal.length)) +
							" : " + HexFormat.ofDelimiter(", ")
									.formatHex(
										Arrays.copyOfRange(bytes, curVal.length, bytes.length)) +
							"]");
					logger.accept(
						"\tWas: [" + HexFormat.ofDelimiter(", ").formatHex(curVal) + "]");
				}
			}
		}

		emuThread.reInitialize();

		emuThread.overrideCounter(func.getEntryPoint());

		return emuThread;
	}
}
