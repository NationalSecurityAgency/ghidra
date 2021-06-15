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
package ghidra.dbg.test;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeNotNull;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

import org.junit.Test;

import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.TargetObjectSchema;

/**
 * Tests the functionality of a register bank
 *
 * <p>
 * Note that multiple sub-cases of this test can be generated to separate
 * testing various types of registers. E.g., one for user registers, one for
 * control registers, another for vector registers, etc. The model developer
 * should be thorough, and decide how best to break the tests down, depending on
 * the mechanism the model uses to read and/or write to each set. Even if
 * different cases are not used, the total register set should exercise all the
 * various register types.
 */
public abstract class AbstractDebuggerModelRegistersTest extends AbstractDebuggerModelTest
		implements RequiresTarget {

	/**
	 * Get the expected (absolute) path of the target's (inner-most) register
	 * bank
	 * 
	 * @param threadPath the path of the target (usually a thread)
	 * @return the expected path, or {@code null} for no assertion
	 */
	public List<String> getExpectedRegisterBankPath(List<String> threadPath) {
		return null;
	}

	/**
	 * This has been a popular convention, and may soon become required
	 * 
	 * <p>
	 * Background: Technically, the descriptions (register container) can be
	 * higher up the model tree, e.g., to apply to an entire process, rather
	 * than to specific threads. Of course, this might imply all threads have
	 * the same set of registers. That assumption seems intuitive, but on some
	 * platforms, e.g., dbgeng with WoW64, some threads may only have the 32-bit
	 * registers available. Even then, a process could present two register
	 * containers, one for the 64-bit and one for the 32-bit registers,
	 * assigning the bank's {@link TargetRegisterBank#getDescriptions()}
	 * attribute accordingly.
	 * 
	 * <p>
	 * However, none of that really matters if you choose the
	 * banks-are-containers convention. The primary motivation for doing this is
	 * to present register values as attributes in the tree. This makes them
	 * accessible from the "Objects" window of the UI, which is significant,
	 * because using the "Registers" window requires the target be recorded into
	 * a trace. Thus, if this test detects that the model's
	 * {@link TargetRegisterBank}s are also {@link TargetRegisterContainer}s,
	 * then this method must return true, and it will further verify the
	 * {@link TargetObject#getValue()} attribute of each register object
	 * correctly reports the same values as
	 * {@link TargetRegisterBank#readRegistersNamed(Collection)}. TODO:
	 * Currently the value is given as a string, encoding the value in base-16.
	 * I'd rather it were a byte array.
	 * 
	 * @return true if the convention is expected and should be tested, false if
	 *         not
	 */
	public boolean isRegisterBankAlsoContainer() {
		return true;
	}

	/**
	 * Get the values to write to the registers
	 * 
	 * <p>
	 * This collection is used for validation in other tests. The descriptions
	 * are validated to have lengths consistent with the written values, and the
	 * read values are expected to have lengths equal to the written values.
	 * 
	 * @return the name-value map to write, and use for validation
	 */
	public abstract Map<String, byte[]> getRegisterWrites();

	/**
	 * This various slightly from the usual find pattern, since we attempt to
	 * find any thread first
	 * 
	 * @param seedPath the path to the target or thread
	 * @return the bank, or {@code null} if one cannot be uniquely identified in
	 *         a thread, or the target
	 * @throws Throwable if anything goes wrong
	 */
	protected TargetRegisterBank findRegisterBank(List<String> seedPath) throws Throwable {
		return m.findWithIndex(TargetRegisterBank.class, "0", seedPath);
	}

	@Test
	public void testRegisterBankIsWhereExpected() throws Throwable {
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		List<String> expectedRegisterBankPath =
			getExpectedRegisterBankPath(target.getPath());
		assumeNotNull(expectedRegisterBankPath);

		TargetRegisterBank bank = findRegisterBank(target.getPath());
		assertEquals(expectedRegisterBankPath, bank.getPath());
	}

	@Test
	public void testBanksAreContainersConventionIsAsExpected() throws Throwable {
		m.build();

		boolean banksAreContainers = true;
		for (TargetObjectSchema schema : m.getModel()
				.getRootSchema()
				.getContext()
				.getAllSchemas()) {
			if (schema.getInterfaces().contains(TargetRegisterBank.class)) {
				banksAreContainers &=
					schema.getInterfaces().contains(TargetRegisterContainer.class);
			}
		}
		assertEquals(isRegisterBankAlsoContainer(), banksAreContainers);
	}

	@Test
	public void testRegistersHaveExpectedSizes() throws Throwable {
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		TargetRegisterBank bank = m.findWithIndex(TargetRegisterBank.class, "0", target.getPath());
		TargetObject descriptions = bank.getDescriptions();
		for (Entry<String, byte[]> ent : getRegisterWrites().entrySet()) {
			String regName = ent.getKey();
			TargetRegister reg =
				m.findWithIndex(TargetRegister.class, regName, descriptions.getPath());
			assertEquals(ent.getValue().length, (reg.getBitLength() + 7) / 8);
		}
	}

	// TODO: Test cases for writing to non-existing registers (by name)

	@Test
	public void testReadRegisters() throws Throwable {
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		TargetRegisterBank bank = m.findWithIndex(TargetRegisterBank.class, "0", target.getPath());
		Map<String, byte[]> exp = getRegisterWrites();
		Map<String, byte[]> read = waitOn(bank.readRegistersNamed(exp.keySet()));
		assertEquals("Not all registers were read, or extras were read", exp.keySet(),
			read.keySet());

		// NB. The specimen is not expected to control the register values. Just validate lengths
		for (String name : exp.keySet()) {
			assertEquals(exp.get(name).length, read.get(name).length);
		}

		if (!isRegisterBankAlsoContainer()) {
			return; // pass
		}

		for (String name : exp.keySet()) {
			expectRegisterObjectValue(bank, name, read.get(name));
		}
	}

	protected void expectRegisterObjectValue(TargetRegisterBank bank, String name, byte[] value)
			throws Throwable {
		retryVoid(() -> {
			TargetRegister reg = m.findWithIndex(TargetRegister.class, name, bank.getPath());
			assertNotNull(reg);
			String actualHex = (String) reg.getValue();
			assertNotNull(actualHex);
			assertEquals(new BigInteger(1, value), new BigInteger(actualHex, 16));
		}, List.of(AssertionError.class));
	}

	@Test
	public void testWriteRegisters() throws Throwable {
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		TargetRegisterBank bank = m.findWithIndex(TargetRegisterBank.class, "0", target.getPath());
		Map<String, byte[]> write = getRegisterWrites();
		waitOn(bank.writeRegistersNamed(write));
		// NB. This only really tests the cache, if applicable. A scenario checks for efficacy.
		Map<String, byte[]> read = waitOn(bank.readRegistersNamed(write.keySet()));
		assertEquals("Not all registers were read, or extras were read", write.keySet(),
			read.keySet());

		for (String name : write.keySet()) {
			assertArrayEquals(write.get(name), read.get(name));
		}

		if (!isRegisterBankAlsoContainer()) {
			return; // pass
		}

		for (String name : write.keySet()) {
			expectRegisterObjectValue(bank, name, read.get(name));
		}
	}
}
