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
package ghidra.program.emulation;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.function.IntUnaryOperator;
import java.util.function.LongToIntFunction;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.MemBufferByteProvider;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.EmulateMemoryStateBuffer;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.LEB128;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import wasm.WasmLoader;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFuncSignature;
import wasm.analysis.WasmFunctionAnalysis;
import wasm.analysis.WasmFunctionAnalysis.StackEffect;
import wasm.format.WasmHeader;
import wasm.format.WasmModule;

public class WasmEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	private static class WasmFunctionAnalysisProvider {
		private AddressSpace codeSpace;
		private WasmModule module;
		private WasmAnalysis analysis;
		private long[] functionAddresses;

		public WasmFunctionAnalysisProvider(AddressFactory addressFactory, MemoryState memoryState) {
			Address moduleAddress = WasmLoader.getModuleAddress(addressFactory);
			codeSpace = moduleAddress.getAddressSpace();
			ByteProvider byteProvider = new MemBufferByteProvider(new EmulateMemoryStateBuffer(memoryState, moduleAddress));

			// Since we don't have a Program context, we have to re-analyze the Wasm module
			// from the memory contents.
			try {
				// XXX Nasty hack to retrieve the length of the Wasm module. Assumes that the
				// memory following the module will be uninitialized, or set to zero.
				BinaryReader reader = new BinaryReader(byteProvider, true);
				new WasmHeader(reader);
				long moduleSize;
				while (true) {
					moduleSize = reader.getPointerIndex();
					int id = reader.readNextUnsignedByte();
					long contentLength = reader.readNext(LEB128::unsigned);
					reader.setPointerIndex(reader.getPointerIndex() + contentLength);
					// A custom section (id 0) must have a name, so a zero-length custom section
					// is invalid. This happens if we have two consecutive null bytes, which
					// suggests that we're at the end of the module.
					if (id == 0 && contentLength == 0) {
						break;
					}
				}

				reader = new BinaryReader(new ByteProviderWrapper(byteProvider, 0, moduleSize), true);
				module = new WasmModule(reader);
			} catch (IOException e) {
				throw new LowlevelError("Unable to parse Wasm module", e);
			}

			analysis = new WasmAnalysis(addressFactory, module);
			List<WasmFuncSignature> functions = analysis.getFunctions();
			functionAddresses = new long[functions.size()];
			for (int i = 0; i < functions.size(); i++) {
				functionAddresses[i] = functions.get(i).getStartAddr().getOffset();
			}
			Arrays.sort(functionAddresses);
		}

		public WasmFunctionAnalysis getAnalysisForAddress(Address address) {
			if (address.getAddressSpace() != codeSpace) {
				return null;
			}

			int index = Arrays.binarySearch(functionAddresses, address.getOffset());
			if (index < 0) {
				/* No exact match, so the index is the negative of the insertion point */
				index = -index - 2;
			}
			if (index < 0 || index >= functionAddresses.length) {
				return null;
			}
			try {
				return analysis.getFunctionAnalysis(codeSpace.getAddress(functionAddresses[index]));
			} catch (IOException e) {
				throw new LowlevelError("Unable to analyze Wasm function", e);
			}
		}
	}

	private WasmFunctionAnalysisProvider analysisProvider;
	private WasmFunctionAnalysis prevAnalysis;
	private Register contextRegister;
	private long localsBase;
	private WasmEmulationHelper helper;

	public WasmEmulateInstructionStateModifier(Emulate emu) {
		super(emu);

		contextRegister = emu.getLanguage().getContextBaseRegister();
		helper = new WasmEmulationHelper(emu.getLanguage());
		localsBase = emu.getLanguage().getRegister("l0").getOffset();

		registerPcodeOpBehavior("funcEntryCallOther", new FuncEntryOpBehaviour());
		registerPcodeOpBehavior("popCallOther", new PopOpBehaviour());
		registerPcodeOpBehavior("pushCallOther", new PushOpBehaviour());
		registerPcodeOpBehavior("callPrologueCallOther", new CallPrologueOpBehaviour());
		registerPcodeOpBehavior("callEpilogueCallOther", new CallEpilogueOpBehaviour());

		registerPcodeOpBehavior("ctz", new BitCountOpBehaviour("ctz", Integer::numberOfTrailingZeros, Long::numberOfTrailingZeros));
		registerPcodeOpBehavior("clz", new BitCountOpBehaviour("clz", Integer::numberOfLeadingZeros, Long::numberOfLeadingZeros));
		registerPcodeOpBehavior("popcnt", new BitCountOpBehaviour("popcnt", Integer::bitCount, Long::bitCount));
	}

	private WasmFunctionAnalysis getAnalysis(Address address) {
		// Optimization: cache the analysis for the current function, so we only need to
		// search if the function changes
		if (prevAnalysis != null) {
			WasmFuncSignature func = prevAnalysis.getSignature();
			if (address.compareTo(func.getStartAddr()) >= 0 && address.compareTo(func.getEndAddr()) <= 0) {
				return prevAnalysis;
			}
		}
		WasmFunctionAnalysis analysis = analysisProvider.getAnalysisForAddress(address);
		if (analysis == null) {
			return null;
		}
		prevAnalysis = analysis;
		return analysis;
	}

	private class BitCountOpBehaviour implements OpBehaviorOther {
		String name;
		IntUnaryOperator i32Func;
		LongToIntFunction i64Func;
		public BitCountOpBehaviour(String name, IntUnaryOperator i32Func, LongToIntFunction i64Func) {
			this.name = name;
			this.i32Func = i32Func;
			this.i64Func = i64Func;
		}

		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			MemoryState memState = emu.getMemoryState();
			if (inputs.length != 2) {
				throw new LowlevelError(name + " requires one input");
			}

			int size = inputs[1].getSize();
			long value = memState.getValue(inputs[1]);
			int result;
			if (size == 4) {
				result = i32Func.applyAsInt((int)value);
			} else if (size == 8) {
				result = i64Func.applyAsInt(value);
			} else {
				throw new LowlevelError(name + " cannot be applied to object of size " + size);
			}

			memState.setValue(out, (long)result);
		}
	}

	private class FuncEntryOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			MemoryState memState = emu.getMemoryState();
			if (inputs.length != 3) {
				throw new LowlevelError("funcEntryCallOther requires two inputs");
			}

			long inputOffset = inputs[1].getOffset();
			long localsOffset = inputs[2].getOffset();
			AddressSpace regSpace = emu.getLanguage().getAddressFactory().getAddressSpace("register");

			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			if (funcAnalysis == null) {
				throw new LowlevelError("Unable to find Wasm function analysis for address " +
						emu.getExecuteAddress());
			}
			int numParams = funcAnalysis.getSignature().getParams().length;
			int numLocals = funcAnalysis.getSignature().getLocals().length;
			helper.copyRegisters(memState, inputOffset, localsOffset, numParams);
			byte[] zero = new byte[WasmLoader.REG_SIZE];
			for(int i=numParams; i<numLocals; i++) {
				memState.setChunk(zero, regSpace, localsOffset + i * WasmLoader.REG_SIZE, zero.length);
			}
		}
	}

	private class PopOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			// Pop operands from stack to a register block
			if (inputs.length != 2) {
				throw new LowlevelError("popCallOther requires one input");
			}

			long baseOffset = inputs[1].getOffset();

			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			if (funcAnalysis == null) {
				throw new LowlevelError("Unable to find Wasm function analysis for address " +
						emu.getExecuteAddress());
			}
			StackEffect stackEffect = funcAnalysis.getStackEffect(emu.getExecuteAddress());
			if (stackEffect == null) {
				return;
			}

			long stackOffset = helper.getStackOffset(stackEffect.getPopHeight());
			int count = stackEffect.getToPop().length;
			helper.copyRegisters(emu.getMemoryState(), stackOffset, baseOffset, count);
		}
	}

	private class PushOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			// Push operands from one register block to stack
			if (inputs.length != 2) {
				throw new LowlevelError("pushCallOther requires one input");
			}

			long baseOffset = inputs[1].getOffset();

			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			if (funcAnalysis == null) {
				throw new LowlevelError("Unable to find Wasm function analysis for address " +
						emu.getExecuteAddress());
			}
			StackEffect stackEffect = funcAnalysis.getStackEffect(emu.getExecuteAddress());
			if (stackEffect == null) {
				return;
			}

			long stackOffset = helper.getStackOffset(stackEffect.getPushHeight());
			int count = stackEffect.getToPush().length;
			helper.copyRegisters(emu.getMemoryState(), baseOffset, stackOffset, count);
		}
	}

	private class CallPrologueOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			MemoryState memState = emu.getMemoryState();
			if (inputs.length != 2) {
				throw new LowlevelError("callPrologueCallOther requires one input");
			}

			long baseOffset = inputs[1].getOffset();

			// Push locals onto shadow stack
			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			if (funcAnalysis == null) {
				throw new LowlevelError("Unable to find Wasm function analysis for address " +
						emu.getExecuteAddress());
			}
			helper.pushShadowStackRegs(memState, localsBase, funcAnalysis.getSignature().getLocals().length);

			// Pop params into i* registers
			StackEffect stackEffect = funcAnalysis.getStackEffect(emu.getExecuteAddress());
			if (stackEffect == null) {
				throw new LowlevelError("Unable to find stack effect for function at " + emu.getExecuteAddress());
			}

			long stackOffset = helper.getStackOffset(stackEffect.getPopHeight());
			int count = stackEffect.getToPop().length;
			helper.copyRegisters(memState, stackOffset, baseOffset, count);

			// Push stack onto shadow stack
			helper.pushShadowStackRegs(memState, helper.getStackOffset(0), stackEffect.getPopHeight());

			// Push LR to shadow stack
			helper.pushShadowStackLR(memState);
		}
	}

	private class CallEpilogueOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			MemoryState memState = emu.getMemoryState();
			if (inputs.length != 2) {
				throw new LowlevelError("callEpilogueCallOther requires one input");
			}

			long baseOffset = inputs[1].getOffset();

			// Pop LR from shadow stack
			helper.popShadowStackLR(memState);

			// Pop outputs into o* registers
			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			StackEffect stackEffect = funcAnalysis.getStackEffect(emu.getExecuteAddress());
			if (stackEffect == null) {
				throw new LowlevelError("Unable to find stack effect for function at " + emu.getExecuteAddress());
			}

			long stackOffset = helper.getStackOffset(stackEffect.getPopHeight());
			int count = stackEffect.getToPop().length;
			helper.copyRegisters(memState, stackOffset, baseOffset, count);

			// Pop stack from shadow stack
			int stackHeight = helper.popShadowStackRegs(memState, helper.getStackOffset(0));

			// Push outputs onto stack
			helper.copyRegisters(memState, baseOffset, helper.getStackOffset(stackHeight), count);

			// Pop locals from shadow stack
			helper.popShadowStackRegs(memState, localsBase);
		}
	}

	private void updateContextValue(Emulate emulate, Address currentAddress) {
		WasmFunctionAnalysis funcAnalysis = getAnalysis(currentAddress);
		if (funcAnalysis == null) {
			return;
		}

		BigInteger context = funcAnalysis.getContext(currentAddress);
		if (context == null) {
			return;
		}

		emulate.setContextRegisterValue(new RegisterValue(contextRegister, context));
	}

	@Override
	public void initialExecuteCallback(Emulate emulate, Address current_address, RegisterValue contextRegisterValue) throws LowlevelError {
		if (analysisProvider == null) {
			analysisProvider = new WasmFunctionAnalysisProvider(emulate.getLanguage().getAddressFactory(), emulate.getMemoryState());
		}

		// Set initial context value
		updateContextValue(emulate, current_address);

		// Set SSP register if not set
		helper.setInitialSSP(emulate.getMemoryState());
	}

	@Override
	public void postExecuteCallback(Emulate emulate, Address lastExecuteAddress, PcodeOp[] lastExecutePcode, int lastPcodeIndex, Address currentAddress) throws LowlevelError {
		updateContextValue(emulate, currentAddress);
	}
}
