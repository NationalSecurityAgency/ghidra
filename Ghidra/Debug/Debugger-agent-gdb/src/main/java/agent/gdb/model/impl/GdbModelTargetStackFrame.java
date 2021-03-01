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
package agent.gdb.model.impl;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbRegister;
import agent.gdb.manager.GdbStackFrame;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.ConversionUtils;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "StackFrame",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	})
public class GdbModelTargetStackFrame extends DefaultTargetObject<TargetObject, GdbModelTargetStack>
		implements TargetStackFrame, TargetRegisterBank, GdbModelSelectableObject {
	public static final String FUNC_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "function";
	public static final String FROM_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "from"; // TODO

	protected static String indexFrame(GdbStackFrame frame) {
		return PathUtils.makeIndex(frame.getLevel());
	}

	protected static String keyFrame(GdbStackFrame frame) {
		return PathUtils.makeKey(indexFrame(frame));
	}

	protected static String computeDisplay(GdbStackFrame frame) {
		// TODO: Alternative formats when function is not known?
		return String.format("#%d 0x%s in %s ()", frame.getLevel(), frame.getAddress().toString(16),
			frame.getFunction());
	}

	protected final GdbModelImpl impl;
	protected final GdbModelTargetThread thread;
	protected final GdbModelTargetInferior inferior;

	protected GdbStackFrame frame;
	protected Address pc;
	protected String func;
	protected String display;

	private final GdbModelTargetStackFrameRegisterContainer registers;

	public GdbModelTargetStackFrame(GdbModelTargetStack stack, GdbModelTargetThread thread,
			GdbModelTargetInferior inferior, GdbStackFrame frame) {
		super(stack.impl, stack, keyFrame(frame), "StackFrame");
		this.impl = stack.impl;
		this.thread = thread;
		this.inferior = inferior;

		this.registers = new GdbModelTargetStackFrameRegisterContainer(this);

		changeAttributes(List.of(),
			List.of(
				registers),
			Map.of(
				DESCRIPTIONS_ATTRIBUTE_NAME, getDescriptions(),
				DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(frame),
				UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED),
			"Initialized");
		setFrame(frame);
	}

	@TargetAttributeType(
		name = GdbModelTargetStackFrameRegisterContainer.NAME,
		required = true,
		fixed = true)
	public GdbModelTargetStackFrameRegisterContainer getRegisters() {
		return registers;
	}

	@Override
	public GdbModelTargetRegisterContainer getDescriptions() {
		return inferior.registers;
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		return inferior.registers.fetchElements().thenCompose(regs -> {
			Set<GdbRegister> toRead = new LinkedHashSet<>();
			for (String regname : names) {
				GdbModelTargetRegister reg = regs.get(regname);
				if (reg == null) {
					throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
				toRead.add(reg.register);
			}
			return frame.readRegisters(toRead);
		}).thenApply(vals -> {
			Map<String, byte[]> result = new LinkedHashMap<>();
			Map<GdbRegister, BigInteger> values = new LinkedHashMap<>();
			for (Map.Entry<GdbRegister, BigInteger> ent : vals.entrySet()) {
				GdbRegister reg = ent.getKey();
				String regName = reg.getName();
				BigInteger val = ent.getValue();
				if (val == null) {
					Msg.warn(this, "Register " + regName + " value came back null.");
					continue;
				}
				byte[] bytes = ConversionUtils.bigIntegerToBytes(reg.getSize(), val);
				values.put(reg, val);
				result.put(regName, bytes);
			}
			registers.setValues(values);
			changeAttributes(List.of(), List.of( //
				registers //
			), Map.of(), "Refreshed");
			listeners.fire(TargetRegisterBankListener.class).registersUpdated(this, result);
			return result;
		});
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		return inferior.registers.fetchElements().thenCompose(regs -> {
			Map<GdbRegister, BigInteger> toWrite = new LinkedHashMap<>();
			for (Map.Entry<String, byte[]> ent : values.entrySet()) {
				String regname = ent.getKey();
				GdbModelTargetRegister reg = regs.get(regname);
				if (reg == null) {
					throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
				BigInteger val = new BigInteger(1, ent.getValue());
				toWrite.put(reg.register, val);
			}
			return frame.writeRegisters(toWrite);
		}).thenAccept(__ -> {
			listeners.fire(TargetRegisterBankListener.class).registersUpdated(this, values);
		});
	}

	protected void setFrame(GdbStackFrame frame) {
		this.pc = impl.space.getAddress(frame.getAddress().longValue());
		this.func = frame.getFunction();
		// TODO: module? "from"
		this.frame = frame;

		changeAttributes(List.of(), List.of( //
			registers //
		), Map.of( //
			PC_ATTRIBUTE_NAME, pc, //
			FUNC_ATTRIBUTE_NAME, func, //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(frame) //
		), "Refreshed");
	}

	protected void invalidateRegisterCaches() {
		listeners.fire.invalidateCacheRequested(this);
	}

	@Override
	@Internal
	public CompletableFuture<Void> select() {
		return frame.select();
	}

	@TargetAttributeType(name = FUNC_ATTRIBUTE_NAME)
	public String getFunction() {
		return func;
	}
}
