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
package ghidra.bitpatterns.info;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;

public class FileBitPatternInfoReaderTest extends AbstractGenericTest {

	private FileBitPatternInfoReader fReader;
	private static final int TOTAL_NUM_FUNCTIONS = 32;
	private static final int TOTAL_NUM_FILES = 2;

	@Before
	public void setUp() throws IOException {
		ResourceFile resourceFile = Application.getModuleDataSubDirectory("BytePatterns", "test");
		fReader = new FileBitPatternInfoReader(resourceFile.getFile(false));
	}

	@Test
	public void testGetNumFiles() {
		assertEquals(TOTAL_NUM_FILES, fReader.getNumFiles());
	}

	@Test
	public void testGetNumFuncs() {
		assertEquals(TOTAL_NUM_FUNCTIONS, fReader.getNumFuncs());
	}

	@Test
	public void testReturnAddresses() {
		List<Long> addresses = fReader.getStartingAddresses();
		Collections.sort(addresses);
		assertEquals(0L, addresses.get(0).longValue());
		assertEquals(0L, addresses.get(1).longValue());
		assertEquals(1L, addresses.get(2).longValue());
		assertEquals(1L, addresses.get(3).longValue());
		assertEquals(2L, addresses.get(4).longValue());
		assertEquals(2L, addresses.get(5).longValue());
		assertEquals(3L, addresses.get(6).longValue());
		assertEquals(3L, addresses.get(7).longValue());
		assertEquals(4L, addresses.get(8).longValue());
		assertEquals(4L, addresses.get(9).longValue());
		assertEquals(5L, addresses.get(10).longValue());
		assertEquals(5L, addresses.get(11).longValue());
		assertEquals(6L, addresses.get(12).longValue());
		assertEquals(6L, addresses.get(13).longValue());
		assertEquals(7L, addresses.get(14).longValue());
		assertEquals(7L, addresses.get(15).longValue());
		assertEquals(8L, addresses.get(16).longValue());
		assertEquals(8L, addresses.get(17).longValue());
		assertEquals(9L, addresses.get(18).longValue());
		assertEquals(9L, addresses.get(19).longValue());
		assertEquals(10L, addresses.get(20).longValue());
		assertEquals(10L, addresses.get(21).longValue());
		assertEquals(11L, addresses.get(22).longValue());
		assertEquals(11L, addresses.get(23).longValue());
		assertEquals(12L, addresses.get(24).longValue());
		assertEquals(12L, addresses.get(25).longValue());
		assertEquals(13L, addresses.get(26).longValue());
		assertEquals(13L, addresses.get(27).longValue());
		assertEquals(14L, addresses.get(28).longValue());
		assertEquals(14L, addresses.get(29).longValue());
		assertEquals(15L, addresses.get(30).longValue());
		assertEquals(15L, addresses.get(31).longValue());
	}

	@Test
	public void testContextRegisterExtent() {
		BigInteger zero = new BigInteger("0");
		BigInteger one = new BigInteger("1");
		BigInteger two = new BigInteger("2");
		BigInteger three = new BigInteger("3");

		ContextRegisterExtent cRegExtent = fReader.getContextRegisterExtent();
		List<String> cRegisters = cRegExtent.getContextRegisters();
		assertEquals(4, cRegisters.size());

		String cReg = cRegisters.get(0);
		assertEquals("cReg1", cReg);
		List<BigInteger> valuesForReg = cRegExtent.getValuesForRegister(cReg);
		assertEquals(1, valuesForReg.size());
		assertEquals(zero, valuesForReg.get(0));

		cReg = cRegisters.get(1);
		assertEquals("cReg2", cReg);
		valuesForReg = cRegExtent.getValuesForRegister(cReg);
		assertEquals(2, valuesForReg.size());
		assertEquals(zero, valuesForReg.get(0));
		assertEquals(one, valuesForReg.get(1));

		cReg = cRegisters.get(2);
		assertEquals("cReg3", cReg);
		valuesForReg = cRegExtent.getValuesForRegister(cReg);
		assertEquals(4, valuesForReg.size());
		assertEquals(zero, valuesForReg.get(0));
		assertEquals(one, valuesForReg.get(1));
		assertEquals(two, valuesForReg.get(2));

		cReg = cRegisters.get(3);
		assertEquals("cReg4", cReg);
		valuesForReg = cRegExtent.getValuesForRegister(cReg);
		assertEquals(8, valuesForReg.size());
		assertEquals(zero, valuesForReg.get(0));
		assertEquals(one, valuesForReg.get(1));
		assertEquals(two, valuesForReg.get(2));
		assertEquals(three, valuesForReg.get(3));
	}

	@Test
	public void testContextRegisterFiltering() {
		//test empty filter
		ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
		List<Long> filteredAddresses = fReader.getFilteredAddresses(cRegFilter);
		assertEquals(TOTAL_NUM_FUNCTIONS, filteredAddresses.size());

		//filter out odd addresses
		cRegFilter.addRegAndValueToFilter("cReg2", new BigInteger("0"));
		filteredAddresses = fReader.getFilteredAddresses(cRegFilter);
		assertEquals(TOTAL_NUM_FUNCTIONS / 2, filteredAddresses.size());

		//now filter out addresses which are not 0 mod 4
		cRegFilter.addRegAndValueToFilter("cReg3", new BigInteger("0"));
		filteredAddresses = fReader.getFilteredAddresses(cRegFilter);
		assertEquals(TOTAL_NUM_FUNCTIONS / 4, filteredAddresses.size());
		Collections.sort(filteredAddresses);
		assertEquals(0L, (long) filteredAddresses.get(0));
		assertEquals(0L, (long) filteredAddresses.get(1));
		assertEquals(4L, (long) filteredAddresses.get(2));
		assertEquals(4L, (long) filteredAddresses.get(3));
		assertEquals(8L, (long) filteredAddresses.get(4));
		assertEquals(8L, (long) filteredAddresses.get(5));
		assertEquals(12L, (long) filteredAddresses.get(6));
		assertEquals(12L, (long) filteredAddresses.get(7));

		//now filter out addresses with are not 1 mod 8 (so nothing should pass)
		cRegFilter.addRegAndValueToFilter("cReg4", new BigInteger("1"));
		filteredAddresses = fReader.getFilteredAddresses(cRegFilter);
		assertEquals(0, filteredAddresses.size());
	}

	//possibly combine ContextRegisterFilter and ContextAction? 	

	//fsReader: re-write to use dummy monitors?  is this possible?		

	//change hashcode method for ditted sequences
	//what to do about bits of check?

	//createTableColumnDescriptor: sort ordinals? no 0

	//context registers: use tracked set?

	//add the ability to filter
	//when sending to XML: add the ability to set these values

	//tail call elimination/sibling call elimination
	//can there be conditional jumps?  probably...
	//change references to the functionStartAnalyzer to refer to a PatternFactory object?
	//possible start code: check whether this is already in the body of function?

	//calc_win7.exe: 100030e0d: write some scripts: is this the start of a block? 
	// it has a label...

	//understand patternfactories, match actions, and context actions
	//PatternFactory: an interface
	//implementing classes: various FunctionStartAnalyzers
	//method to get a match action by name and a post rule by name
	//MatchAction: this is an action that should be applied to a program at an
	//address where the pattern matches, such as setting a context register
	//PostRule: this is a rule to check after the pattern matches, such
	//as whether the address alignment is correct	

	//evaluation:
	//  scripts to evaluate patterns over repositories?
	//  modify the script that already exists?

	//SequenceMiningParams: save these to properties

	//write help, submit

	//possible future improvements:
	//  yellow node if not all of the paths continue on?
	//  add tool tips for everything: buttons, tabs?
	//  minimum percentage rounding error - this is not really an error.
	//    comes from the casting on line 147 of ClosedPatternRowObject.java

}
