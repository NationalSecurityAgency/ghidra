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
package agent.frida.model;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.util.*;
import java.util.Map.Entry;

import org.junit.Ignore;
import org.junit.Test;

import agent.frida.model.iface2.FridaModelTargetProcess;
import agent.frida.model.impl.FridaModelTargetThreadContainerImpl;
import ghidra.dbg.target.*;
import ghidra.dbg.test.*;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForFridaX64RegistersTest
		extends AbstractDebuggerModelRegistersTest
		implements ProvidesTargetViaLaunchSpecimen {
	public final Map<String, byte[]> REG_VALS = Map.ofEntries(
		Map.entry("rax", arr("0123456789abcdef")),
		Map.entry("rsp", arr("0123456789abcdef")));

	@Override
	public AbstractDebuggerModelTest getTest() {
		return this;
	}

	@Override
	public boolean isRegisterBankAlsoContainer() {
		return true;
	}

	@Override
	public List<String> getExpectedRegisterBankPath(List<String> threadPath) {
		return PathUtils.extend(threadPath, PathUtils.parse("Registers"));
	}

	@Override
	public Map<String, byte[]> getRegisterWrites() {
		return REG_VALS;
	}

	@Override
	public DebuggerTestSpecimen getLaunchSpecimen() {
		return FridaLinuxSpecimen.SPIN_STRIPPED;
	}

	@Override
	protected TargetObject maybeSubstituteThread(TargetObject target) throws Throwable {
		FridaModelTargetProcess fproc = (FridaModelTargetProcess) target;
		waitOn(fproc.resume());
		FridaModelTargetThreadContainerImpl threads =
			(FridaModelTargetThreadContainerImpl) fproc.getCachedAttribute("Threads");
		waitOn(threads.fetchElements());
		TargetThread thread = findAnyThread(target.getPath());
		return thread == null ? target : thread;
	}

	@Override
	@Ignore
	@Test
	public void testRegistersHaveExpectedSizes() throws Throwable {
		// Disabled as of 220609
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		Map<List<String>, TargetRegisterBank> banks = findRegisterBanks(target.getPath());
		for (TargetRegisterBank bank : banks.values()) {
			List<String> path = bank.getPath();
			for (Entry<String, byte[]> ent : getRegisterWrites().entrySet()) {
				String regName = ent.getKey();
				Map<List<String>, TargetRegister> regs = m.findAll(TargetRegister.class,
					path, pred -> pred.applyKeys(regName), false);
				for (TargetRegister reg : regs.values()) {
					assertEquals(ent.getValue().length, (reg.getBitLength() + 7) / 8);
				}
			}
		}
	}

	@Override
	@Ignore
	@Test
	public void testRegisterBankIsWhereExpected() throws Throwable {
		// Disabled as of 220609
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		List<String> expectedRegisterBankPath =
			getExpectedRegisterBankPath(target.getPath());
		assumeNotNull(expectedRegisterBankPath);

		Map<List<String>, TargetRegisterBank> banks = findRegisterBanks(target.getPath());
		for (TargetRegisterBank bank : banks.values()) {
			List<String> path = bank.getPath();
			assertTrue(path.containsAll(expectedRegisterBankPath));
		}
	}

	@Override
	@Ignore
	@Test
	public void testReadRegisters() throws Throwable {
		// Disabled as of 220609
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		TargetRegisterContainer c = Objects.requireNonNull(
			m.findWithIndex(TargetRegisterContainer.class, "0", target.getPath()));
		Map<List<String>, TargetRegisterBank> banks =
			m.findAll(TargetRegisterBank.class, c.getPath(), true);
		Map<String, byte[]> exp = getRegisterWrites();
		Map<String, byte[]> read = new HashMap<>();
		for (TargetRegisterBank bank : banks.values()) {
			for (String name : exp.keySet()) {
				Map<List<String>, TargetRegister> regs = m.findAll(TargetRegister.class,
					bank.getPath(), pred -> pred.applyKeys(name), false);
				for (TargetRegister reg : regs.values()) {
					byte[] bytes = waitOn(bank.readRegister(reg));
					read.put(name, bytes);
					expectRegisterObjectValue(bank, name, bytes);
					assertEquals(exp.get(name).length, bytes.length);
				}
			}
		}
		assertEquals("Not all registers were read, or extras were read", exp.keySet(),
			read.keySet());
	}

	@Override
	@Ignore
	@Test
	public void testWriteRegisters() throws Throwable {
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		TargetRegisterContainer c = Objects.requireNonNull(
			m.findWithIndex(TargetRegisterContainer.class, "0", target.getPath()));
		Map<List<String>, TargetRegisterBank> banks =
			m.findAll(TargetRegisterBank.class, c.getPath(), true);
		Map<String, byte[]> write = getRegisterWrites();
		Map<String, byte[]> read = new HashMap<>();
		for (TargetRegisterBank bank : banks.values()) {
			for (String name : write.keySet()) {
				Map<List<String>, TargetRegister> regs = m.findAll(TargetRegister.class,
					bank.getPath(), pred -> pred.applyKeys(name), false);
				for (TargetRegister reg : regs.values()) {
					waitOn(bank.writeRegister(reg, write.get(name)));

					// NB. This only really tests the cache, if applicable. A scenario checks for efficacy.
					byte[] bytes = waitOn(bank.readRegister(reg));
					read.put(name, bytes);
					expectRegisterObjectValue(bank, name, bytes);
					assertArrayEquals(write.get(name), bytes);
				}
			}
		}
		assertEquals("Not all registers were read, or extras were read", write.keySet(),
			read.keySet());
	}

	@Override
	@Ignore
	@Test
	public void testBanksAreContainersConventionIsAsExpected() throws Throwable {
		// Disabled as of 220609
	}

}
