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
import java.util.stream.Collectors;

import agent.gdb.manager.GdbRegister;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.ConversionUtils;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "RegisterValueContainer",
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class GdbModelTargetStackFrameRegisterContainer
		extends DefaultTargetObject<GdbModelTargetStackFrameRegister, GdbModelTargetStackFrame>
		implements TargetRegisterContainer, TargetRegisterBank {
	public static final String NAME = "Registers";

	protected final GdbModelImpl impl;
	protected final GdbModelTargetStackFrame frame;
	protected final GdbModelTargetThread thread;

	private Map<String, byte[]> regValues = new HashMap<>();

	protected final Map<Integer, GdbModelTargetStackFrameRegister> registersByNumber =
		new WeakValueHashMap<>();
	protected final Set<GdbRegister> allRegisters = new LinkedHashSet<>();

	public GdbModelTargetStackFrameRegisterContainer(GdbModelTargetStackFrame frame) {
		super(frame.impl, frame, NAME, "StackFrameRegisterContainer");
		this.impl = frame.impl;
		this.frame = frame;
		this.thread = frame.thread;

		changeAttributes(List.of(), List.of(), Map.of(DESCRIPTIONS_ATTRIBUTE_NAME, this),
			"Initialized");
	}

	@Override
	public GdbModelTargetStackFrameRegisterContainer getDescriptions() {
		return this;
	}

	protected CompletableFuture<Map<String, GdbModelTargetStackFrameRegister>> ensureRegisterDescriptions() {
		if (elements.isEmpty()) {
			return populateRegisterDescriptions().thenApply(__ -> elements);
		}
		return CompletableFuture.completedFuture(elements);
	}

	/**
	 * Get the descriptors without populating the values
	 * 
	 * <p>
	 * This need only be called once, but values must be updated every STOPPED/read
	 */
	protected CompletableFuture<Void> populateRegisterDescriptions() {
		return thread.thread.listRegisters().thenAccept(regs -> {
			if (!valid) {
				return;
			}
			if (regs.size() != registersByNumber.size()) {
				allRegisters.clear();
				registersByNumber.clear();
			}
			allRegisters.addAll(regs);
			List<GdbModelTargetStackFrameRegister> registers;
			synchronized (this) {
				registers = regs.stream().map(this::getTargetRegister).collect(Collectors.toList());
			}
			setElements(registers, Map.of(), "Refreshed");
		});
	}

	protected CompletableFuture<Map<String, byte[]>> updateRegisterValues(Set<GdbRegister> toRead) {
		return frame.frame.readRegisters(toRead).thenApply(vals -> {
			Map<String, byte[]> result = new LinkedHashMap<>();
			for (Map.Entry<GdbRegister, BigInteger> ent : vals.entrySet()) {
				GdbRegister reg = ent.getKey();
				String regName = reg.getName();
				BigInteger val = ent.getValue();
				if (val == null) {
					Msg.warn(this, "Register " + regName + " value came back null.");
					continue;
				}
				byte[] bytes = ConversionUtils.bigIntegerToBytes(reg.getSize(), val);
				result.put(regName, bytes);
				elements.get(regName).stateChanged(bytes);
			}
			this.regValues = result;
			listeners.fire.registersUpdated(this, result);
			return result;
		});
	}

	/**
	 * Does both descriptions and then populates values
	 */
	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		// NB. GDB manager caches these per thread
		return ensureRegisterDescriptions().thenCompose(regs -> {
			if (!regs.isEmpty()) {
				return updateRegisterValues(allRegisters);
			}
			return AsyncUtils.nil();
		}).thenApply(__ -> null);
	}

	protected synchronized GdbModelTargetStackFrameRegister getTargetRegister(
			GdbRegister register) {
		return registersByNumber.computeIfAbsent(register.getNumber(),
			n -> new GdbModelTargetStackFrameRegister(this, register));
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		return model.gateFuture(ensureRegisterDescriptions().thenCompose(regs -> {
			Set<GdbRegister> toRead = new LinkedHashSet<>();
			for (String regname : names) {
				GdbModelTargetStackFrameRegister reg = regs.get(regname);
				if (reg == null) {
					throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
				toRead.add(reg.register);
			}
			return updateRegisterValues(toRead);
		}));
	}

	@Override
	public Map<String, byte[]> getCachedRegisters() {
		return regValues;
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		Map<GdbRegister, BigInteger> toWrite = new LinkedHashMap<>();
		return model.gateFuture(ensureRegisterDescriptions().thenCompose(regs -> {
			for (Map.Entry<String, byte[]> ent : values.entrySet()) {
				String regname = ent.getKey();
				GdbModelTargetStackFrameRegister reg = regs.get(regname);
				if (reg == null) {
					throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
				BigInteger val = new BigInteger(1, ent.getValue());
				toWrite.put(reg.register, val);
			}
			return frame.frame.writeRegisters(toWrite);
		}).thenCompose(__ -> {
			return updateRegisterValues(toWrite.keySet());
		})).thenApply(__ -> null);
	}

	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {
		return requestElements(false).exceptionally(ex -> {
			if (!valid) {
				Msg.info(this,
					"Ignoring error when refreshing now-invalid thread registers: " + ex);
			}
			else {
				impl.reportError(this, "Trouble updating registers on state change", ex);
			}
			return null;
		});
	}
}
