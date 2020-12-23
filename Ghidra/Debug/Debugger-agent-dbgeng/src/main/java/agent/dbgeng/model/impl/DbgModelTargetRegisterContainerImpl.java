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
package agent.dbgeng.model.impl;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgRegister;
import agent.dbgeng.manager.impl.DbgRegisterSet;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibility;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.util.ConversionUtils;

public class DbgModelTargetRegisterContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetRegisterContainerAndBank {

	protected final DbgThread thread;

	protected final Map<Integer, DbgModelTargetRegister> registersByNumber = new HashMap<>();
	protected final Map<String, DbgModelTargetRegister> registersByName = new HashMap<>();

	public DbgModelTargetRegisterContainerImpl(DbgModelTargetThread thread) {
		super(thread.getModel(), thread, "Registers", "RegisterContainer");
		this.thread = thread.getThread();

		changeAttributes(List.of(), List.of(), Map.of( //
			TargetRegisterBank.DESCRIPTIONS_ATTRIBUTE_NAME, this //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return thread.listRegisters().thenAccept(regs -> {
			if (regs.size() != registersByNumber.size()) {
				registersByNumber.clear();
				registersByName.clear();
			}
			List<TargetObject> registers;
			synchronized (this) {
				registers = regs.stream().map(this::getTargetRegister).collect(Collectors.toList());
			}
			setElements(registers, Map.of(), "Refreshed");
			if (!getCachedElements().isEmpty()) {
				readRegistersNamed(getCachedElements().keySet());
			}
		});
	}

	@Override
	public synchronized DbgModelTargetRegister getTargetRegister(DbgRegister register) {
		DbgModelTargetRegister reg = registersByNumber.computeIfAbsent(register.getNumber(),
			n -> new DbgModelTargetRegisterImpl(this, register));
		registersByName.put(register.getName(), reg);
		return reg;
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		return AsyncUtils.sequence(TypeSpec.map(String.class, byte[].class)).then(seq -> {
			thread.listRegisters().handle(seq::next);
		}, TypeSpec.cls(DbgRegisterSet.class)).then((regs, seq) -> {
			if (regs.size() != registersByNumber.size() || getCachedElements().isEmpty()) {
				requestElements(true).handle(seq::next);
			}
			seq.next(null, null);
		}).then(seq -> {
			Set<DbgRegister> toRead = new LinkedHashSet<>();
			for (String regname : names) {
				DbgModelTargetRegister reg = registersByName.get(regname);
				if (reg != null) {
					DbgRegister register = reg.getRegister();
					//if (register.isBaseRegister()) {
					toRead.add(register);
					//}
					//throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
			}
			thread.readRegisters(toRead).handle(seq::next);
		}, TypeSpec.map(DbgRegister.class, BigInteger.class)).then((vals, seq) -> {
			Map<String, byte[]> result = new LinkedHashMap<>();
			for (DbgRegister dbgReg : vals.keySet()) {
				DbgModelTargetRegister reg = registersByNumber.get(dbgReg.getNumber());
				String oldval = (String) reg.getCachedAttributes().get(VALUE_ATTRIBUTE_NAME);
				BigInteger value = vals.get(dbgReg);
				byte[] bytes = ConversionUtils.bigIntegerToBytes(dbgReg.getSize(), value);
				result.put(dbgReg.getName(), bytes);
				reg.changeAttributes(List.of(), Map.of( //
					VALUE_ATTRIBUTE_NAME, value.toString(16) //
				), "Refreshed");
				if (value.longValue() != 0) {
					String newval = reg.getName() + " : " + value.toString(16);
					reg.changeAttributes(List.of(), Map.of( //
						DISPLAY_ATTRIBUTE_NAME, newval //
					), "Refreshed");
					reg.setModified(!value.toString(16).equals(oldval));
				}
			}
			listeners.fire(TargetRegisterBankListener.class).registersUpdated(this, result);
			seq.exit(result);
		}).finish();
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			thread.listRegisters().handle(seq::next);
		}, TypeSpec.cls(DbgRegisterSet.class)).then((regs, seq) -> {
			fetchElements().handle(seq::nextIgnore);
		}).then(seq -> {
			Map<String, ? extends TargetObjectRef> regs = getCachedElements();
			Map<DbgRegister, BigInteger> toWrite = new LinkedHashMap<>();
			for (Map.Entry<String, byte[]> ent : values.entrySet()) {
				String regname = ent.getKey();
				DbgModelTargetRegister reg = (DbgModelTargetRegister) regs.get(regname);
				if (reg == null) {
					throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
				BigInteger val = new BigInteger(1, ent.getValue());
				toWrite.put(reg.getRegister(), val);
			}
			thread.writeRegisters(toWrite).handle(seq::next);
			// TODO: Should probably filter only effective and normalized writes in the callback
		}).then(seq -> {
			listeners.fire(TargetRegisterBankListener.class).registersUpdated(this, values);
			seq.exit();
		}).finish();
	}

	/*
	public void invalidateRegisterCaches() {
		listeners.fire.invalidateCacheRequested(this);
	}
	*/

	@Override
	public void onRunning() {
		// NB: We don't want to do this apparently
		//invalidateRegisterCaches();
		setAccessibility(TargetAccessibility.INACCESSIBLE);
	}

	@Override
	public void onStopped() {
		setAccessibility(TargetAccessibility.ACCESSIBLE);
		if (thread.equals(getManager().getEventThread())) {
			readRegistersNamed(getCachedElements().keySet());
		}
	}
}
