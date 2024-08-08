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

import java.math.BigInteger;

import ghidra.app.emulator.Emulator;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import wasm.WasmLoader;

/** Class to manage Wasm stack and shadow stack semantics for emulation. */
public class WasmEmulationHelper {
    /*
     * The shadow stack grows towards higher addresses. Each saved frame is
     * structured as follows:
     * 
     * [l0, l1, ..., lL-2, lL-1] [L] [s0, s1, ..., sS-2, sS-1] [S] [LR]
     */
    private AddressSpace regSpace;
    private long stackBase;
    private long inputsBase;
    private long localsBase;
    private Register sspRegister;
    private Register lrRegister;
    private Language language;

    public WasmEmulationHelper(Language language) {
        this.language = language;
        sspRegister = language.getRegister("SSP");
        lrRegister = language.getRegister("LR");
        regSpace = language.getAddressFactory().getAddressSpace("register");
        stackBase = language.getRegister("s0").getOffset();
        inputsBase = language.getRegister("i0").getOffset();
        localsBase = language.getRegister("l0").getOffset();
    }

    public void simulateCall(Emulator emulator, long retAddress, long funcAddress, long... inputs) {
        BigInteger[] biInputs = new BigInteger[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            biInputs[i] = BigInteger.valueOf(inputs[i]);
        }
        simulateCall(emulator, retAddress, funcAddress, biInputs);
    }

    /**
     * Simulate a function call. Call this before emulating a WASM function, and
     * the call will return to retAddress when it completes.
     * 
     * @param emulate
     *            the emulation context
     * @param retAddress
     *            the address to which the function will return on completion
     * @param funcAddress
     *            the address of the function to call
     * @param inputs
     *            the inputs to provide to the function
     */
    public void simulateCall(Emulator emulator, long retAddress, long funcAddress, BigInteger... inputs) {
        MemoryState memState = emulator.getMemState();

        setInitialSSP(memState);

        // Push dummy locals
        pushShadowStackRegs(memState, 0, 0);
        // Push dummy stack
        pushShadowStackRegs(memState, 0, 0);
        // Push target LR
        memState.setValue(lrRegister, retAddress);
        pushShadowStackLR(memState);

        // Set inputs
        for (int i = 0; i < inputs.length; i++) {
            memState.setValue(regSpace, inputsBase + i * WasmLoader.REG_SIZE, WasmLoader.REG_SIZE, inputs[i]);
        }

        // Set up for call
        memState.setValue(emulator.getPCRegisterName(), funcAddress);
        emulator.setExecuteAddress(funcAddress);
    }

    public void simulateReturn(Emulator emulator, long... outputs) {
        BigInteger[] biOutputs = new BigInteger[outputs.length];
        for (int i = 0; i < outputs.length; i++) {
            biOutputs[i] = BigInteger.valueOf(outputs[i]);
        }
        simulateReturn(emulator, biOutputs);
    }

    /**
     * Simulate a return from a function. This can be useful for e.g. simulating
     * imported functions.
     * 
     * @param emulate
     *            the emulation context
     * @param outputs
     *            the function outputs to push onto the caller's stack. The number
     *            of outputs must match the function signature.
     */
    public void simulateReturn(Emulator emulator, BigInteger... outputs) {
        MemoryState memState = emulator.getMemState();

        // Pop LR from shadow stack
        popShadowStackLR(memState);

        // Pop shadow stack into stack
        int stackHeight = popShadowStackRegs(memState, getStackOffset(0));

        // Push outputs onto stack
        for (int i = 0; i < outputs.length; i++) {
            memState.setValue(regSpace, getStackOffset(stackHeight + i), WasmLoader.REG_SIZE, outputs[i]);
        }

        // Pop shadow locals into locals
        popShadowStackRegs(memState, localsBase);

        // Return to caller
        long lr = memState.getValue(lrRegister);
        memState.setValue(emulator.getPCRegisterName(), lr);
        emulator.setExecuteAddress(lr);
    }

    /** Get offset of stack register by index */
    public long getStackOffset(int count) {
        return stackBase + count * WasmLoader.REG_SIZE;
    }

    public void copyRegisters(MemoryState memState, long sourceOffset, long destOffset, int count) {
        byte[] data = new byte[count * WasmLoader.REG_SIZE];
        memState.getChunk(data, regSpace, sourceOffset, data.length, false);
        memState.setChunk(data, regSpace, destOffset, data.length);
    }

    public void pushShadowStackRegs(MemoryState memState, long sourceOffset, int count) {
        long sspVal = memState.getValue(sspRegister);
        memState.setValue(sspRegister, sspVal + WasmLoader.REG_SIZE * (count + 1));

        byte[] data = new byte[count * WasmLoader.REG_SIZE];
        memState.getChunk(data, regSpace, sourceOffset, data.length, false);
        memState.setChunk(data, regSpace, sspVal, data.length);
        memState.setValue(regSpace, sspVal + data.length, 4, count);
    }

    public int popShadowStackRegs(MemoryState memState, long destOffset) {
        long sspVal = memState.getValue(sspRegister);
        int count = (int) memState.getValue(regSpace, sspVal - WasmLoader.REG_SIZE, 4);
        sspVal -= WasmLoader.REG_SIZE * (count + 1);
        memState.setValue(sspRegister, sspVal);

        byte[] data = new byte[count * WasmLoader.REG_SIZE];
        memState.getChunk(data, regSpace, sspVal, data.length, false);
        memState.setChunk(data, regSpace, destOffset, data.length);
        return count;
    }

    public void pushShadowStackLR(MemoryState memState) {
        long sspVal = memState.getValue(sspRegister);
        memState.setValue(sspRegister, sspVal + WasmLoader.REG_SIZE);
        long lrVal = memState.getValue(lrRegister);
        memState.setValue(regSpace, sspVal, lrRegister.getNumBytes(), lrVal);
    }

    public void popShadowStackLR(MemoryState memState) {
        long sspVal = memState.getValue(sspRegister) - WasmLoader.REG_SIZE;
        memState.setValue(sspRegister, sspVal);
        long lrVal = memState.getValue(regSpace, sspVal, lrRegister.getNumBytes());
        memState.setValue(lrRegister, lrVal);
    }

    public void setInitialSSP(MemoryState memState) {
        long value = memState.getValue(sspRegister);
        if (value == 0) {
            memState.setValue(sspRegister, language.getRegister("ss0").getOffset());
        }
    }
}
