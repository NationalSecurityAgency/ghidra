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
package ghidra.program.util;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * 
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class AddressEvaluatorTest extends AbstractGhidraHeadedIntegrationTest {

	AddressFactory addrFactory;

	public AddressEvaluatorTest() {
		super();
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Test
	public void testEval() throws Exception {
		Program p = createDefaultProgram("Test", ProgramBuilder._TOY_LE, this);
		addrFactory = p.getAddressFactory();
		int txId = p.startTransaction("Test");
		try {
			assertEquals(addr("0x19"), AddressEvaluator.evaluate(p, "(2+3)*5"));
			assertEquals(addr("0x11"), AddressEvaluator.evaluate(p, "2+3*5"));
			assertEquals(addr("0x11"), AddressEvaluator.evaluate(p, "2+(3*5)"));
			assertEquals(addr("0x11"), AddressEvaluator.evaluate(p, "(2+3*5)"));
			assertEquals(addr("0x16"), AddressEvaluator.evaluate(p, "0x11+5"));
			assertEquals(addr("0x02"), AddressEvaluator.evaluate(p, "2-1+1"));
			assertEquals(addr("0x5"), AddressEvaluator.evaluate(p, "5"));
			assertEquals(addr("0x3"), AddressEvaluator.evaluate(p, "0-5+8"));
			assertEquals(addr("0x3"), AddressEvaluator.evaluate(p, "-5+8"));
			assertEquals(addr("0xfffffffB"), AddressEvaluator.evaluate(p, "-5"));
			assertEquals(addr("0x11"), AddressEvaluator.evaluate(p, "3+(5+(3*2)+(3))"));
			assertEquals(addr("0xff00"), AddressEvaluator.evaluate(p, "0xffff ^ 0xff"));
			assertEquals(addr("0x123f"), AddressEvaluator.evaluate(p, "0xffff & 0x123f"));
			assertEquals(addr("0x1234"), AddressEvaluator.evaluate(p, "0x1200 | 0x0034"));
			assertEquals(addr("0xffffffff"), AddressEvaluator.evaluate(p, "~ 0x0"));
			assertEquals(addr("0x1201"), AddressEvaluator.evaluate(p, "0x1200 | ~(0xfffffffe)"));
			assertEquals(addr("0x480"), AddressEvaluator.evaluate(p, "0x1200 >> 2"));
			assertEquals(addr("0x1200"), AddressEvaluator.evaluate(p, "0x480 << 2"));

			assertEquals(addr("0x1"), AddressEvaluator.evaluate(p, "(((0x1 | 0x2) & 0x2) == 0x2)"));
			assertEquals(addr("0x0"), AddressEvaluator.evaluate(p, "(((0x1 | 0x2) & 0x2) == 0x1)"));
			assertEquals(addr("0x0"), AddressEvaluator.evaluate(p, "(((0x1 | 0x2) & 0x2) == 0x1)"));

			assertEquals(addr("0x1"), AddressEvaluator.evaluate(p, "(((0x1 | 0x2) & 0x2) >= 0x1)"));
			assertEquals(addr("0x0"), AddressEvaluator.evaluate(p, "(((0x1 | 0x2) & 0x2) <= 0x1)"));

			Symbol s = p.getSymbolTable().createLabel(addr("0x100"), "entry", SourceType.IMPORTED);
			Address a = s.getAddress();
			a = a.add(10);
			assertEquals(a, AddressEvaluator.evaluate(p, "entry+5*2"));
			assertEquals(addr("0x101"), AddressEvaluator.evaluate(p, "entry + (entry == 0x100)"));
			assertEquals(addr("0x500"), AddressEvaluator.evaluate(p,
				"entry + (entry == 0x100) * 0x400 + (entry < 0x100) * 0x500"));
			assertEquals(addr("0x600"), AddressEvaluator.evaluate(p,
				"entry + (entry > 0x100) * 0x400 + (entry <= 0x100) * 0x500"));
		}
		finally {
			p.endTransaction(txId, true);
			p.release(this);
		}
	}

	@Test
	public void testMultiAddrSpace() throws Exception {
		Program p = createDefaultProgram("Test", ProgramBuilder._TOY_LE, this);
		addrFactory = p.getAddressFactory();
		try {
			assertEquals(addr("0x19"), AddressEvaluator.evaluate(p, "(2+3)*5"));
			assertEquals(addr("0x11"), AddressEvaluator.evaluate(p, "2+3*5"));
			assertEquals(addr("0x11"), AddressEvaluator.evaluate(p, "2+(3*5)"));
			assertEquals(addr("RAM:15"), AddressEvaluator.evaluate(p, "RAM:2 + 0x13"));
		}
		finally {
			p.release(this);
		}
	}
}
