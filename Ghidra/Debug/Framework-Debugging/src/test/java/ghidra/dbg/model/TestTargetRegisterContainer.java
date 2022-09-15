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
import java.util.function.Predicate;

import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

public class TestTargetRegisterContainer
		extends DefaultTestTargetObject<TestTargetRegister, TestTargetProcess>
		implements TargetRegisterContainer {

	private final Set<AbstractTestTargetRegisterBank<?>> banks = new HashSet<>();

	public TestTargetRegisterContainer(TestTargetProcess parent) {
		super(parent, "Registers", "RegisterContainer");
	}

	public Map<String, TestTargetRegister> getDescs() {
		return elements;
	}

	public List<TestTargetRegister> addRegistersFromLanguage(Language language,
			Predicate<Register> predicate) {
		List<TestTargetRegister> add = new ArrayList<>();
		for (Register register : language.getRegisters()) {
			if (!predicate.test(register)) {
				continue;
			}
			add.add(getModel().newTestTargetRegister(this, register));
		}
		String reason = "Added registers from Ghidra language: " + language;
		changeElements(List.of(), add, reason);
		List<AbstractTestTargetRegisterBank<?>> banks;
		synchronized (this.banks) {
			banks = List.copyOf(this.banks);
		}
		for (AbstractTestTargetRegisterBank<?> bank : banks) {
			bank.addRegisterDescs(add, reason);
		}
		return add;
	}

	public TestTargetRegister addRegister(Register register) {
		TestTargetRegister tr =
			getModel().newTestTargetRegister(this, Objects.requireNonNull(register));
		String reason = "Added " + register + " from Ghidra language";
		changeElements(List.of(), List.of(tr), reason);
		List<AbstractTestTargetRegisterBank<?>> banks;
		synchronized (this.banks) {
			banks = List.copyOf(this.banks);
		}
		for (AbstractTestTargetRegisterBank<?> bank : banks) {
			bank.addRegisterDescs(List.of(tr), reason);
		}
		return tr;
	}

	public Delta<TestTargetRegister, TestTargetRegister> removeRegister(Register register,
			String reason) {
		Delta<TestTargetRegister, TestTargetRegister> result =
			changeElements(List.of(register.getName()), List.of(), reason);
		List<AbstractTestTargetRegisterBank<?>> banks;
		synchronized (this.banks) {
			banks = List.copyOf(this.banks);
		}
		for (AbstractTestTargetRegisterBank<?> bank : banks) {
			bank.removeRegisterDescs(result.removed.values(), reason);
		}
		return result;
	}

	public void addBank(AbstractTestTargetRegisterBank<?> bank) {
		synchronized (this.banks) {
			this.banks.add(bank);
		}
	}
}
