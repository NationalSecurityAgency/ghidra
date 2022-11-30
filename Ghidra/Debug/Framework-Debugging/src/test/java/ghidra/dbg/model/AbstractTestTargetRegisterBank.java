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

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.util.PathUtils;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;

public abstract class AbstractTestTargetRegisterBank<P extends TestTargetObject>
		extends DefaultTestTargetObject<TestTargetObject, P>
		implements TargetRegisterBank, TargetRegisterContainer {

	// TODO: Remove the separate descriptors idea
	protected final TestTargetRegisterContainer descs;
	public final Map<String, byte[]> regVals = new HashMap<>();

	public AbstractTestTargetRegisterBank(P parent, String name, String typeHint,
			TestTargetRegisterContainer regs) {
		super(parent, name, typeHint);
		this.descs = regs;
		this.descs.addBank(this);
		changeAttributes(List.of(), Map.of(
			DESCRIPTIONS_ATTRIBUTE_NAME, this),
			"Initialized");
		initializeValues();
	}

	public abstract TestTargetThread getThread();

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		if (!descs.getDescs().keySet().containsAll(names)) {
			throw new DebuggerRegisterAccessException("No such register");
		}
		Map<String, byte[]> result = new LinkedHashMap<>();
		for (String n : names) {
			byte[] v = regVals.get(n);
			if (v == null) {
				v = descs.getDescs().get(n).defaultValue();
			}
			result.put(n, v);
		}
		populateObjectValues(result, "Read registers");
		return model.gateFuture(descs.getModel().future(result).thenApply(__ -> {
			broadcast().registersUpdated(this, result);
			return result;
		}));
	}

	protected CompletableFuture<Void> writeRegs(Map<String, byte[]> values,
			Consumer<Address> setPC) {
		if (!descs.getDescs().keySet().containsAll(values.keySet())) {
			throw new DebuggerRegisterAccessException("No such register");
		}
		Map<String, byte[]> updates = new LinkedHashMap<>();
		CompletableFuture<Void> future = descs.getModel().future(null);
		for (Map.Entry<String, byte[]> ent : values.entrySet()) {
			String n = ent.getKey();
			TestTargetRegister desc = descs.getDescs().get(n);
			byte[] v = desc.normalizeValue(ent.getValue());
			regVals.put(n, v);
			updates.put(n, v);
			if (desc.isPC()) {
				future.thenAccept(__ -> {
					setPC.accept(desc.parseAddress(v));
				});
			}
		}
		populateObjectValues(updates, "Write registers");
		future.thenAccept(__ -> {
			broadcast().registersUpdated(this, updates);
		});
		return model.gateFuture(future);
	}

	protected void addObjectValues(Collection<TestTargetRegister> descs, String reason) {
		Set<TestTargetRegisterValue> objVals = new HashSet<>();
		for (TestTargetRegister rd : descs) {
			if (attributes.containsKey(rd.getName())) {
				continue;
			}
			TestTargetRegisterValue tv = new TestTargetRegisterValue(this, rd, (BigInteger) null);
			objVals.add(tv);
		}
		changeAttributes(List.of(), objVals, Map.of(), reason);
	}

	protected void removeObjectValues(Collection<TestTargetRegister> descs, String reason) {
		List<String> toRemove = new ArrayList<>();
		for (TestTargetRegister rd : descs) {
			toRemove.add(PathUtils.parseIndex(rd.getName()));
		}
		changeAttributes(toRemove, Map.of(), reason);
	}

	protected void populateObjectValues(Map<String, byte[]> values, String reason) {
		Set<TestTargetRegisterValue> objVals = new HashSet<>();
		for (Map.Entry<String, byte[]> ent : values.entrySet()) {
			TestTargetRegister rd = descs.getDescs().get(ent.getKey());
			byte[] value = ent.getValue();
			TestTargetRegisterValue tv = new TestTargetRegisterValue(this, rd,
				value == null ? null : Utils.bytesToBigInteger(value, rd.byteLength, true, false));
			objVals.add(tv);
		}
		changeAttributes(List.of(), objVals, Map.of(), reason);
	}

	protected void initializeValues() {
		Map<String, byte[]> values = new HashMap<>();
		for (TestTargetRegister desc : descs.getDescs().values()) {
			values.put(desc.getIndex(), null);
		}
		populateObjectValues(values, "Populate");
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

	public void addRegisterDescs(Collection<TestTargetRegister> added, String reason) {
		addObjectValues(added, reason);
	}

	public void removeRegisterDescs(Collection<TestTargetRegister> removed, String reason) {
		removeObjectValues(removed, reason);
	}
}
