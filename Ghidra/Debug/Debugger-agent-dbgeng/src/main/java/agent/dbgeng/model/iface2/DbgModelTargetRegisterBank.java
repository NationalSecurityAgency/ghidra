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
package agent.dbgeng.model.iface2;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.*;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.util.ConversionUtils;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

public interface DbgModelTargetRegisterBank extends DbgModelTargetObject, TargetRegisterBank {

	public DbgModelTargetRegister getTargetRegister(DbgRegister register);

	@Override
	public default CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		return getModel().gateFuture(doReadRegistersNamed(names));
	}

	public default CompletableFuture<? extends Map<String, byte[]>> doReadRegistersNamed(
			Collection<String> names) {
		DbgManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			Msg.warn(this,
				"Cannot process command readRegistersNamed while engine is waiting for events");
		}

		AtomicReference<Map<DbgRegister, DbgModelTargetRegister>> read = new AtomicReference<>();
		return getManager().getRegisterMap(getPath()).thenCompose(valueMap -> {
			Map<String, ?> regs = getCachedAttributes();
			Map<DbgRegister, DbgModelTargetRegister> map =
				new HashMap<DbgRegister, DbgModelTargetRegister>();

			for (String regname : names) {
				Object x = regs.get(regname);
				if (!(x instanceof DbgModelTargetRegister)) {
					continue;
				}
				if (!valueMap.containsKey(regname)) {
					continue;
				}
				DbgModelTargetRegister reg = (DbgModelTargetRegister) x;
				DbgRegister register = (DbgRegister) valueMap.get(regname);
				if (register != null) {
					map.put(register, reg);
				}
			}
			read.set(map);
			return getParentThread().getThread().readRegisters(map.keySet());
		}).thenApply(vals -> {
			Map<String, byte[]> result = new LinkedHashMap<>();
			for (DbgRegister dbgReg : vals.keySet()) {
				DbgModelTargetRegister reg = read.get().get(dbgReg);
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
					reg.setModified(value.toString(16).equals(oldval));
				}
			}
			ListenerSet<DebuggerModelListener> listeners = getListeners();
			if (listeners != null) {
				listeners.fire.registersUpdated(getProxy(), result);
			}
			return result;
		});
	}

	@Override
	public default CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		return getModel().gateFuture(doWriteRegistersNamed(values));
	}

	public default CompletableFuture<Void> doWriteRegistersNamed(Map<String, byte[]> values) {
		DbgThread thread = getParentThread().getThread();
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			requestNativeElements().handle(seq::nextIgnore);
		}).then(seq -> {
			thread.listRegisters().handle(seq::next);
		}, TypeSpec.cls(DbgRegisterSet.class)).then((regset, seq) -> {
			Map<String, ?> regs = getCachedAttributes();
			Map<DbgRegister, BigInteger> toWrite = new LinkedHashMap<>();
			for (Map.Entry<String, byte[]> ent : values.entrySet()) {
				String regname = ent.getKey();
				DbgModelTargetRegister reg = (DbgModelTargetRegister) regs.get(regname);
				if (reg == null) {
					throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
				BigInteger val = new BigInteger(1, ent.getValue());
				DbgRegister dbgreg = regset.get(regname);
				toWrite.put(dbgreg, val);
			}
			getParentThread().getThread().writeRegisters(toWrite).handle(seq::next);
			// TODO: Should probably filter only effective and normalized writes in the callback
		}).then(seq -> {
			getListeners().fire.registersUpdated(getProxy(), values);
			seq.exit();
		}).finish();
	}

	@Override
	public default Map<String, byte[]> getCachedRegisters() {
		return getValues();
	}

	public default Map<String, byte[]> getValues() {
		Map<String, byte[]> result = new HashMap<>();
		for (Entry<String, ?> entry : this.getCachedAttributes().entrySet()) {
			if (entry.getValue() instanceof DbgModelTargetRegister) {
				DbgModelTargetRegister reg = (DbgModelTargetRegister) entry.getValue();
				byte[] bytes = reg.getBytes();
				result.put(entry.getKey(), bytes);
			}
		}
		return result;
	}

}
