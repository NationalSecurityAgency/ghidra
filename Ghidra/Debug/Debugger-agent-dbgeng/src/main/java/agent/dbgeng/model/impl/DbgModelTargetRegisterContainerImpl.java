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

import agent.dbgeng.manager.*;
import agent.dbgeng.manager.impl.DbgRegister;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.util.ConversionUtils;

@TargetObjectSchemaInfo(
	name = "RegisterContainer",
	elements = {
		@TargetElementType(type = DbgModelTargetRegisterImpl.class) },
	elementResync = ResyncMode.ONCE, //
	attributes = {
		@TargetAttributeType(
			name = TargetRegisterBank.DESCRIPTIONS_ATTRIBUTE_NAME,
			type = DbgModelTargetRegisterContainerImpl.class),
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class DbgModelTargetRegisterContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetRegisterContainerAndBank {

	protected final DbgThread thread;

	protected final Map<String, DbgModelTargetRegister> registersByName = new HashMap<>();

	private Map<String, byte[]> values = new HashMap<>();

	public DbgModelTargetRegisterContainerImpl(DbgModelTargetThread thread) {
		super(thread.getModel(), thread, "Registers", "RegisterContainer");
		this.thread = thread.getThread();

		requestElements(false);
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetRegisterBank.DESCRIPTIONS_ATTRIBUTE_NAME, this //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return thread.listRegisters().thenAccept(regs -> {
			if (regs.size() != registersByName.size()) {
				DbgModelImpl impl = (DbgModelImpl) model;
				for (DbgRegister reg : regs) {
					impl.deleteModelObject(reg);
				}
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

	public void threadStateChangedSpecific(DbgState state, DbgReason reason) {
		if (!state.equals(DbgState.RUNNING)) {
			readRegistersNamed(getCachedElements().keySet());
		}
	}

	@Override
	public synchronized DbgModelTargetRegister getTargetRegister(DbgRegister register) {
		DbgModelImpl impl = (DbgModelImpl) model;
		TargetObject modelObject = impl.getModelObject(register);
		if (modelObject != null) {
			return (DbgModelTargetRegister) modelObject;
		}
		DbgModelTargetRegister reg = new DbgModelTargetRegisterImpl(this, register);
		registersByName.put(register.getName(), reg);
		return reg;
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		return model.gateFuture(thread.listRegisters().thenCompose(regs -> {
			if (regs.size() != registersByName.size() || getCachedElements().isEmpty()) {
				return requestElements(false);
			}
			return AsyncUtils.NIL;
		}).thenCompose(__ -> {
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
			return thread.readRegisters(toRead);
		}).thenApply(vals -> {
			Map<String, byte[]> result = new LinkedHashMap<>();
			for (DbgRegister dbgReg : vals.keySet()) {
				DbgModelTargetRegister reg = getTargetRegister(dbgReg);
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
			this.values = result;
			listeners.fire.registersUpdated(getProxy(), result);
			return result;
		}));
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		return model.gateFuture(thread.listRegisters().thenCompose(regs -> {
			return requestElements(false);
		}).thenCompose(__ -> {
			Map<String, ? extends TargetObject> regs = getCachedElements();
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
			return thread.writeRegisters(toWrite);
			// TODO: Should probably filter only effective and normalized writes in the callback
		}).thenAccept(__ -> {
			listeners.fire.registersUpdated(getProxy(), values);
		}));
	}

	public Map<String, byte[]> getCachedRegisters() {
		return values;
	}

}
