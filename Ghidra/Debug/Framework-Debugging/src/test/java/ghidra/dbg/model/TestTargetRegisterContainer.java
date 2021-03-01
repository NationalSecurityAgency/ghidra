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
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

public class TestTargetRegisterContainer
		extends DefaultTestTargetObject<TestTargetRegister, TestTargetProcess>
		implements TargetRegisterContainer {

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
			add.add(TestTargetRegister.fromLanguageRegister(this, register));
		}
		changeElements(List.of(), add, "Added registers from Ghidra language: " + language);
		return add;
	}

	public TestTargetRegister addRegister(Register register) {
		TestTargetRegister tr = TestTargetRegister.fromLanguageRegister(this, register);
		changeElements(List.of(), List.of(tr), "Added " + register + " from Ghidra language");
		return tr;
	}
}
