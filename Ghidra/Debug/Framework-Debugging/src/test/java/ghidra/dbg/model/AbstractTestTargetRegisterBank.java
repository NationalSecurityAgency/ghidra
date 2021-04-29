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
package ghidra.dbg.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.program.model.address.Address;

public abstract class AbstractTestTargetRegisterBank<P extends TestTargetObject>
		extends DefaultTestTargetObject<TestTargetObject, P> implements TargetRegisterBank {

	protected final TestTargetRegisterContainer regs;
	public final Map<String, byte[]> regVals = new HashMap<>();

	public AbstractTestTargetRegisterBank(P parent, String name, String typeHint,
			TestTargetRegisterContainer regs) {
		super(parent, name, typeHint);
		this.regs = regs;
		changeAttributes(List.of(), Map.of(
			DESCRIPTIONS_ATTRIBUTE_NAME, regs //
		), "Initialized");
	}

	public abstract TestTargetThread getThread();

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		if (!regs.getDescs().keySet().containsAll(names)) {
			throw new DebuggerRegisterAccessException("No such register");
		}
		Map<String, byte[]> result = new LinkedHashMap<>();
		for (String n : names) {
			byte[] v = regVals.get(n);
			if (v == null) {
				v = regs.getDescs().get(n).defaultValue();
			}
			result.put(n, v);
		}
		return model.gateFuture(regs.getModel().future(result).thenApply(__ -> {
			listeners.fire.registersUpdated(this, result);
			return result;
		}));
	}

	protected CompletableFuture<Void> writeRegs(Map<String, byte[]> values,
			Consumer<Address> setPC) {
		if (!regs.getDescs().keySet().containsAll(values.keySet())) {
			throw new DebuggerRegisterAccessException("No such register");
		}
		Map<String, byte[]> updates = new LinkedHashMap<>();
		CompletableFuture<Void> future = regs.getModel().future(null);
		for (Map.Entry<String, byte[]> ent : values.entrySet()) {
			String n = ent.getKey();
			TestTargetRegister desc = regs.getDescs().get(n);
			byte[] v = desc.normalizeValue(ent.getValue());
			regVals.put(n, v);
			updates.put(n, v);
			if (desc.isPC()) {
				future.thenAccept(__ -> {
					setPC.accept(desc.parseAddress(v));
				});
			}
		}
		future.thenAccept(__ -> {
			listeners.fire.registersUpdated(this, updates);
		});
		return model.gateFuture(future);
	}

	public void setFromBank(AbstractTestTargetRegisterBank<?> bank) {
		//Map<String, byte[]> updates = new HashMap<>();
		//updates.putAll(bank.regVals);
		regVals.putAll(bank.regVals);
		for (Iterator<String> kit = regVals.keySet().iterator(); kit.hasNext();) {
			String key = kit.next();
			if (bank.regVals.containsKey(key)) {
				continue;
			}
			//updates.put(key, regs.getDescs().get(key).defaultValue());
			kit.remove();
		}
	}
}
