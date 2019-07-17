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
package ghidra.app.analyzers;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CondenseFillerBytesAnalyzerTest extends AbstractGenericTest {

	private ProgramDB program;
	private ToyProgramBuilder builder;

	public CondenseFillerBytesAnalyzerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		builder = new ToyProgramBuilder("Test", true);
		builder.createMemory(".text", "0x0", 0x1000);
		program = builder.getProgram();
	}

	@Test
	public void testDetermineFillerValue_SinglePattern() throws Exception {

		String fillerPattern = createAndInstallFillerPattern_SinglePattern();

		CondenseFillerBytesAnalyzer analyzer = new CondenseFillerBytesAnalyzer();
		Listing listing = program.getListing();
		String autoFiller = analyzer.determineFillerValue(listing);
		assertEquals(fillerPattern, autoFiller);
	}

	@Test
	public void testDetermineFillerValue_TwoPatterns() throws Exception {
		//
		// When there are multiple filler bytes, the most frequent one will be used.
		//

		String fillerPattern = createAndInstallFillerPattern_TwoPatterns();

		CondenseFillerBytesAnalyzer analyzer = new CondenseFillerBytesAnalyzer();
		Listing listing = program.getListing();
		String autoFiller = analyzer.determineFillerValue(listing);
		assertEquals(fillerPattern, autoFiller);
	}

	@Test
	public void testCollapseFillerBytes_SingleByte() throws Exception {

		List<FillerFunction> fillerFunctions = installFillerPattern_SingleByte();

		runAnalyzer();

		for (FillerFunction ff : fillerFunctions) {
			ff.assertFilledCorrectly();
		}
	}

	@Test
	public void testCollapseFillerBytes_MultipleByte() throws Exception {

		List<FillerFunction> fillerFunctions = installFillerPattern_MultipleBytes();

		runAnalyzer();

		for (FillerFunction ff : fillerFunctions) {
			ff.assertFilledCorrectly();
		}
	}

	@Test
	public void testCollapseFillerBytes_WithAndWithoutFillerBytes() throws Exception {
		//
		// Test that functions without filler bytes are not modified
		//

		List<FillerFunction> fillerFunctions = installFillerPattern_WithAndWithoutFillerBytes();

		runAnalyzer();

		for (FillerFunction ff : fillerFunctions) {
			ff.assertFilledCorrectly();
		}
	}

	@Test
	public void testCustomFillValueMatchingPatternsGetChanged() throws Exception {

		String customPattern = "01";
		List<FillerFunction> fillerFunctions = installFillPattern_01(customPattern);

		runAnalyzer(customPattern);

		for (FillerFunction ff : fillerFunctions) {
			ff.assertAlignmentTypeApplied();
		}
	}

	@Test
	public void testCustomFillValue_NonMatchingPatternsDoNotGetChanged() throws Exception {

		// use a filler pattern that does not match our pattern below
		String customPattern = "AB";
		List<FillerFunction> fillerFunctions = installFillPattern_01(customPattern);

		runAnalyzer(customPattern);

		for (FillerFunction ff : fillerFunctions) {
			ff.assertAlignmentTypeNotApplied();
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	/**
	 * Creates filler bytes of 01.  
	 * 
	 * @param searchPattern the pattern that will be used to find filler bytes.  This value is
	 *        used to determine whether the functions created by this method are expected
	 *        to match the filler bytes.
	 */
	private List<FillerFunction> installFillPattern_01(String searchPattern) throws Exception {
		List<FillerFunction> result = new ArrayList<>();

		//
		// 00 filler byte
		//
		int count = 2;
		Function f1 = builder.createEmptyFunction("function1", "0x10", 10, new VoidDataType());
		AddressSetView body = f1.getBody();
		Address max = body.getMaxAddress();
		String actualPattern = "01";
		boolean isFillerFound = searchPattern.equals(actualPattern);
		result.add(new FillerFunction(f1, count, isFillerFound));

		Address fillerAddress = max.next();
		setBytes(fillerAddress, actualPattern, count);

		return result;
	}

	private List<FillerFunction> installFillerPattern_WithAndWithoutFillerBytes() throws Exception {

		List<FillerFunction> result = new ArrayList<>();

		Function f1 = builder.createEmptyFunction("function1", "0x10", 10, new VoidDataType());
		AddressSetView body = f1.getBody();
		Address max = body.getMaxAddress();

		//
		// Filler 1
		//
		int count = 3;
		result.add(new FillerFunction(f1, count));

		Address fillerAddress = max.next();
		String pattern = "90";
		setBytes(fillerAddress, pattern, count);

		//
		// Filler 2
		//
		count = 2;
		Function f2 = builder.createEmptyFunction("function2", "0x40", 10, new VoidDataType());
		body = f2.getBody();
		max = body.getMaxAddress();
		result.add(new FillerFunction(f2, count));

		fillerAddress = max.next();
		setBytes(fillerAddress, pattern, count);

		//
		// No Filler - existing DT
		//
		Function f3 = builder.createEmptyFunction("function3", "0x120", 10, new VoidDataType());
		body = f3.getBody();
		max = body.getMaxAddress();
		result.add(new FillerFunction(f3, count, false));

		fillerAddress = max.next();

		// with a DT applied, filler will not be placed
		builder.applyDataType(fillerAddress.toString(), new ByteDataType());

		//
		// Other Filler (different bytes)
		//
		count = 2;
		Function f5 = builder.createEmptyFunction("function5", "0x200", 10, new VoidDataType());
		body = f5.getBody();
		max = body.getMaxAddress();
		result.add(new FillerFunction(f5, count, false));

		fillerAddress = max.next();
		pattern = "00";
		setBytes(fillerAddress, pattern, count);

		return result;
	}

	private List<FillerFunction> installFillerPattern_MultipleBytes() throws Exception {

		List<FillerFunction> result = new ArrayList<>();

		Function f1 = builder.createEmptyFunction("function1", "0x10", 10, new VoidDataType());
		AddressSetView body = f1.getBody();
		Address max = body.getMaxAddress();

		int count = 3;
		result.add(new FillerFunction(f1, count));

		Address fillerAddress = max.next();
		String pattern = "90";
		setBytes(fillerAddress, pattern, count);

		return result;
	}

	private void setBytes(Address a, String pattern, int count) throws Exception {
		String addr = a.toString();
		for (int i = 0; i < count; i++) {
			builder.setBytes(addr, pattern);
			a = a.next();
			addr = a.toString();
		}
	}

	private List<FillerFunction> installFillerPattern_SingleByte() throws Exception {
		Function f1 = builder.createEmptyFunction("function1", "0x10", 10, new VoidDataType());
		AddressSetView body = f1.getBody();
		Address max = body.getMaxAddress();

		Address fillerAddress = max.next();
		String addr = fillerAddress.toString();
		String pattern = "90";
		builder.setBytes(addr, pattern);

		return Arrays.asList(new FillerFunction(f1, 1));
	}

	private String createAndInstallFillerPattern_SinglePattern() throws Exception {
		// 
		// The filler is located after a function, at undefined data.
		//

		Function f1 = builder.createEmptyFunction("function1", "0x10", 10, new VoidDataType());
		AddressSetView body = f1.getBody();
		Address max = body.getMaxAddress();

		Address fillerAddress = max.next();
		String addr = fillerAddress.toString();
		String pattern = "ba";
		builder.setBytes(addr, "ba");

		return pattern;
	}

	private String createAndInstallFillerPattern_TwoPatterns() throws Exception {
		// 
		// The filler is located after a function, at undefined data.
		//

		Function f1 = builder.createEmptyFunction("function1", "0x10", 10, new VoidDataType());
		AddressSetView body = f1.getBody();
		Address max = body.getMaxAddress();

		Address fillerAddress = max.next();
		String addr = fillerAddress.toString();
		String pattern = "ba";
		builder.setBytes(addr, pattern);

		Function f2 = builder.createEmptyFunction("function2", "0x20", 10, new VoidDataType());
		body = f2.getBody();
		max = body.getMaxAddress();

		// apply this pattern twice so that it occurs more frequently
		pattern = "ee";
		fillerAddress = max.next();
		addr = fillerAddress.toString();
		builder.setBytes(addr, pattern);

		Function f3 = builder.createEmptyFunction("function3", "0x30", 10, new VoidDataType());
		body = f3.getBody();
		max = body.getMaxAddress();

		fillerAddress = max.next();
		addr = fillerAddress.toString();
		builder.setBytes(addr, pattern);

		return pattern;
	}

	private void runAnalyzer() throws CancelledException {
		runAnalyzer(null);
	}

	private void runAnalyzer(String fillerValue) throws CancelledException {
		int txID = program.startTransaction("Analyze");

		try {
			CondenseFillerBytesAnalyzer analyzer = new CondenseFillerBytesAnalyzer();

			if (fillerValue != null) {
				analyzer.fillerValue = fillerValue;
			}

			analyzer.added(program, new AddressSet(), TaskMonitor.DUMMY, new MessageLog());
		}
		finally {
			program.endTransaction(txID, true);
		}
	}

	private class FillerFunction {

		private Function function;
		private int fillerByteCount;
		private boolean isValid = true;// turned-off by known non-matching filler patterns

		FillerFunction(Function f, int count) {
			this.function = f;
			this.fillerByteCount = count;
		}

		public FillerFunction(Function f, int count, boolean isValid) {
			this.function = f;
			this.fillerByteCount = count;
			this.isValid = isValid;
		}

		Address getFillerStart() {
			AddressSetView body = function.getBody();
			return body.getMaxAddress().next();
		}

		/**
		 * Asserts filler bytes are collapsed if the function represented by this class
		 * had filler bytes to be collapsed.   Otherwise, assert that filler bytes were
		 * not applied.
		 */
		void assertFilledCorrectly() {
			if (isValid) {
				assertAlignmentTypeApplied();
			}
			else {
				assertAlignmentTypeNotApplied();
			}
		}

		void assertAlignmentTypeApplied() {
			assertTrue(isValid);

			Address fillerAddress = getFillerStart();
			Listing listing = program.getListing();
			Data data = listing.getDataAt(fillerAddress);

			DataType dt = data.getDataType();
			assertTrue("Filler bytes not collapsed at function " + function,
				dt instanceof AlignmentDataType);
			assertEquals(fillerByteCount, data.getLength());
		}

		void assertAlignmentTypeNotApplied() {
			assertFalse(isValid);

			Address fillerAddress = getFillerStart();
			Listing listing = program.getListing();
			Data data = listing.getDataAt(fillerAddress);

			if (data != null) {
				DataType dt = data.getDataType();
				assertFalse(dt instanceof AlignmentDataType);
			}
		}
	}
}
