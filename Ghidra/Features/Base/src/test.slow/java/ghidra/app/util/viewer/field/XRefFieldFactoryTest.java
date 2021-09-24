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
package ghidra.app.util.viewer.field;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.junit.*;

import docking.widgets.fieldpanel.field.FieldElement;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.table.GhidraProgramTableModel;

public class XRefFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	private CodeBrowserPlugin cb;
	private Options fieldOptions;

	private int callerCount;
	private int functionWithNoCalls;
	private int functionCalledByOneOtherFunction;
	private int functionCalledByMultipleFunctions;
	private int functionWithAllTypesOfCalls;
	private int nonFunctionOffset;

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		env.launchDefaultTool(program);
		cb = env.getPlugin(CodeBrowserPlugin.class);
		fieldOptions = cb.getFormatManager().getFieldOptions();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private ProgramDB buildProgram() throws Exception {
		builder = new ProgramBuilder("test", ProgramBuilder._TOY, this);
		builder.createMemory(".text", "0x0", 0x100000);

		/*
		 	Create a few functions that call other functions
		 	
		 	Create some function calls outside of functions
		 */

		int callerOffset = 0x20000;
		Function caller1 = caller(callerOffset);
		Function caller2 = caller(callerOffset + 1000);
		Function caller3 = caller(callerOffset + 2000);
		Function caller4 = caller(callerOffset + 3000);
		Function caller5 = caller(callerOffset + 4000);
		Function caller6 = caller(callerOffset + 5000);

		// function with no calls
		functionWithNoCalls = 0x0000;
		function(functionWithNoCalls);

		// function called by one function once
		functionCalledByOneOtherFunction = 0x1000;
		function(functionCalledByOneOtherFunction);
		createCallerReference(functionCalledByOneOtherFunction, caller1, 1);

		// function called by multiple functions multiple times each
		functionCalledByMultipleFunctions = 0x2000;
		function(functionCalledByMultipleFunctions);
		createCallerReference(functionCalledByMultipleFunctions, caller2, 3);
		createCallerReference(functionCalledByMultipleFunctions, caller3, 5);

		// function called my multiple functions multiple times each and calls from not in functions
		functionWithAllTypesOfCalls = 0x3000;
		function(functionWithAllTypesOfCalls);
		createCallerReference(functionWithAllTypesOfCalls, caller4, 2);
		createCallerReference(functionWithAllTypesOfCalls, caller5, 5);
		createCallerReference(functionWithAllTypesOfCalls, caller6, 3);

		nonFunctionOffset = 0x30000;
		createNonFunctionReferences(functionWithAllTypesOfCalls, nonFunctionOffset, 10);

		return builder.getProgram();
	}

	@Test
	public void testXrefs_DefaultView() {

		/*
		 	 XREF[20]:    callerFunction4:00020bbc(c),
		                  callerFunction4:00020bc0(c),
		                  callerFunction5:00020fa4(c),
		                  callerFunction5:00020fa8(c),
		                  callerFunction5:00020fac(c),
		                  callerFunction5:00020fb0(c),
		                  callerFunction5:00020fb4(c),
		                  callerFunction6:0002138c(c),
		                  callerFunction6:00021390(c),
		                  callerFunction6:00021394(c),
		                  00030004(c), 00030008(c),
		                  0003000c(c), 00030010(c),
		                  00030014(c), 00030018(c),
		                  0003001c(c), 00030020(c),
		                  00030024(c), 00030028(c)
		 */

		setGroupByFunctionOption(false);

		goToXrefField(functionWithAllTypesOfCalls);

		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertContainsRow(tf, "callerFunction4:00020bbc(c)");
		assertContainsRow(tf, "00030004(c), 00030008(c),");
	}

	@Test
	public void testXrefs_GroupByFunctionView_CallsFromInFunctionsOnly() {

		/*
		 	 XREF[8]:     callerFunction2[3]: 000203ec(c),
		                  callerFunction3[5]: 000207d4(c),
		 */

		setGroupByFunctionOption(true);

		goToXrefField(functionCalledByMultipleFunctions);

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(2, tf.getNumRows());
		assertContainsRow(tf, "callerFunction2[3]: 000203ec(c)");
		assertContainsRow(tf, "allerFunction3[5]: 000207d4(c)");
	}

	@Test
	public void testXrefs_GroupByFunctionView_CallsFromInFunctionsAndNotInFunctions() {

		/*
		 	 XREF[20]:    callerFunction4[2]: 00020bbc(c),
		                  callerFunction5[5]: 00020fa4(c),
		                  callerFunction6[3]: 0002138c(c),
		                  00030004(c), 00030008(c),
		                  0003000c(c), 00030010(c),
		                  00030014(c), 00030018(c),
		                  0003001c(c), 00030020(c),
		                  00030024(c), 00030028(c)
		 */

		setGroupByFunctionOption(true);

		goToXrefField(functionWithAllTypesOfCalls);

		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertContainsRow(tf, "callerFunction4[2]: 00020bbc(c)");
		assertContainsRow(tf, "callerFunction5[5]: 00020fa4(c)");
		assertContainsRow(tf, "00030004(c), 00030008(c),");
	}

	@Test
	public void testXrefs_DefaultView_NoXrefs() {

		setGroupByFunctionOption(false);

		assertFalse(hasXrefField(functionWithNoCalls));
	}

	@Test
	public void testXrefs_DefaultView_DoubleClickFunctionName() {

		/*
		 	 XREF[20]:    callerFunction4:00020bbc(c),
		                  callerFunction4:00020bc0(c),
		                  callerFunction5:00020fa4(c),
		                  callerFunction5:00020fa8(c),
		                  callerFunction5:00020fac(c),
		                  callerFunction5:00020fb0(c),
		                  callerFunction5:00020fb4(c),
		                  callerFunction6:0002138c(c),
		                  callerFunction6:00021390(c),
		                  callerFunction6:00021394(c),
		                  00030004(c), 00030008(c),
		                  0003000c(c), 00030010(c),
		                  00030014(c), 00030018(c),
		                  0003001c(c), 00030020(c),
		                  00030024(c), 00030028(c)
		 */

		setGroupByFunctionOption(false);

		String callerFunction = "callerFunction4";
		goToXrefField(functionWithAllTypesOfCalls, callerFunction);

		doubleClick();

		assertInFunction(callerFunction);
	}

	@Test
	public void testXrefs_GroupByFunctionView_DoubleClickFunctionName() {

		/*
		 	 XREF[20]:    callerFunction4[2]: 00020bbc(c),
		                  callerFunction5[5]: 00020fa4(c),
		                  callerFunction6[3]: 0002138c(c),
		                  00030004(c), 00030008(c),
		                  0003000c(c), 00030010(c),
		                  00030014(c), 00030018(c),
		                  0003001c(c), 00030020(c),
		                  00030024(c), 00030028(c)
		 */

		setGroupByFunctionOption(true);

		goToXrefField(functionWithAllTypesOfCalls);

		String callerFunction = "callerFunction6";
		goToXrefField(functionWithAllTypesOfCalls, callerFunction);

		doubleClick();

		assertInFunction(callerFunction);
	}

	@Test
	public void testXrefs_GroupByFunctionView_DoubleClickAddressInFunction() {

		/*
		 	 XREF[20]:    callerFunction4[2]: 00020bbc(c),
		                  callerFunction5[5]: 00020fa4(c),
		                  callerFunction6[3]: 0002138c(c),
		                  00030004(c), 00030008(c),
		                  0003000c(c), 00030010(c),
		                  00030014(c), 00030018(c),
		                  0003001c(c), 00030020(c),
		                  00030024(c), 00030028(c)
		 */

		setGroupByFunctionOption(true);

		goToXrefField(functionWithAllTypesOfCalls);

		String callerFunction = "callerFunction5";
		goToXrefField(functionWithAllTypesOfCalls, "00020fa4");

		doubleClick();

		assertInFunction(callerFunction);
	}

	@Test
	public void testXrefs_DefaultView_DoubleClickAddressNotInFunction() {

		/*
		 XREF[20]:    callerFunction4:00020bbc(c),
		              callerFunction4:00020bc0(c),
		              callerFunction5:00020fa4(c),
		              callerFunction5:00020fa8(c),
		              callerFunction5:00020fac(c),
		              callerFunction5:00020fb0(c),
		              callerFunction5:00020fb4(c),
		              callerFunction6:0002138c(c),
		              callerFunction6:00021390(c),
		              callerFunction6:00021394(c),
		              00030004(c), 00030008(c),
		              0003000c(c), 00030010(c),
		              00030014(c), 00030018(c),
		              0003001c(c), 00030020(c),
		              00030024(c), 00030028(c)
		*/

		setGroupByFunctionOption(false);

		goToXrefField(functionWithAllTypesOfCalls);

		String addressNotInFunction = "00030018";
		goToXrefField(functionWithAllTypesOfCalls, addressNotInFunction);

		doubleClick();

		assertAtAddress(addressNotInFunction);
	}

	@Test
	public void testXrefs_GroupByFunctionView_DoubleClickAddressNotInFunction() {

		/*
		 	 XREF[20]:    callerFunction4[2]: 00020bbc(c),
		                  callerFunction5[5]: 00020fa4(c),
		                  callerFunction6[3]: 0002138c(c),
		                  00030004(c), 00030008(c),
		                  0003000c(c), 00030010(c),
		                  00030014(c), 00030018(c),
		                  0003001c(c), 00030020(c),
		                  00030024(c), 00030028(c)
		 */

		setGroupByFunctionOption(true);

		goToXrefField(functionWithAllTypesOfCalls);

		String addressNotInFunction = "00030018";
		goToXrefField(functionWithAllTypesOfCalls, addressNotInFunction);

		doubleClick();

		assertAtAddress(addressNotInFunction);
	}

	@Test
	public void testXrefs_DefaultView_DoubleClickToShowAllXrefs() {

		/*
		 XREF[20]:    callerFunction4:00020bbc(c),
		              callerFunction4:00020bc0(c),
		              callerFunction5:00020fa4(c),
		              callerFunction5:00020fa8(c),
		              callerFunction5:00020fac(c),
		              callerFunction5:00020fb0(c),
		              callerFunction5:00020fb4(c),
		              callerFunction6:0002138c(c),
		              callerFunction6:00021390(c),
		              callerFunction6:00021394(c),
		              00030004(c), 00030008(c),
		              0003000c(c), 00030010(c),
		              00030014(c), 00030018(c),
		              0003001c(c), 00030020(c),
		              00030024(c), 00030028(c)
		*/

		setGroupByFunctionOption(false);

		goToXrefHeaderField(functionWithAllTypesOfCalls);

		doubleClick();

		assertTableShowing();
	}

	@Test
	public void testXrefs_GroupByFunctionView_DoubleClickToShowAllXrefs() {

		/*
		 	 XREF[20]:    callerFunction4[2]: 00020bbc(c),
		                  callerFunction5[5]: 00020fa4(c),
		                  callerFunction6[3]: 0002138c(c),
		                  00030004(c), 00030008(c),
		                  0003000c(c), 00030010(c),
		                  00030014(c), 00030018(c),
		                  0003001c(c), 00030020(c),
		                  00030024(c), 00030028(c)
		 */

		setGroupByFunctionOption(true);

		goToXrefHeaderField(functionWithAllTypesOfCalls);

		doubleClick();

		assertTableShowing();
	}

	@Test
	public void testXrefs_DefaultView_DoubleClick_More_Text() {

		/*
		 XREF[20]:    callerFunction4:00020bbc(c),
		              callerFunction4:00020bc0(c),
		              callerFunction5:00020fa4(c),
		              callerFunction5:00020fa8(c),
		              callerFunction5:00020fac(c),
		              callerFunction5:00020fb0(c),
		              [more]
		*/

		setGroupByFunctionOption(false);
		setMaxXrefs(5);

		goToXrefField(functionWithAllTypesOfCalls, "more");

		doubleClick();

		assertTableShowing();
	}

	@Test
	public void testXrefs_GroupByFunctionView_DoubleClick_More_Text() {

		/*
		 XREF[20]:    callerFunction4[2]: 00020bbc(c),
		              callerFunction5[4]: 00020fa4(c),
		              [more]
		*/

		setGroupByFunctionOption(true);
		setMaxXrefs(5);

		goToXrefField(functionWithAllTypesOfCalls, "more");

		doubleClick();

		assertTableShowing();
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertTableShowing() {
		TableComponentProvider<?> table = waitForComponentProvider(TableComponentProvider.class);
		GhidraProgramTableModel<?> model = table.getModel();
		waitForCondition(() -> model.getRowCount() > 0);
	}

	private void assertAtAddress(String expected) {
		Address actual = cb.getCurrentAddress();
		assertEquals(expected, actual.toString());
	}

	private void assertInFunction(String text) {

		Address addr = cb.getCurrentAddress();
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(addr);
		assertEquals(text, function.getName());
	}

	private void doubleClick() {
		click(cb, 2, true);
	}

	private void assertContainsRow(ListingTextField tf, String text) {
		assertTrue("Expected '" + tf.getText() + "' to contain '" + text + "'",
			tf.getText().contains(text));
	}

	private void goToXrefField(int addrOffset) {
		assertTrue("Unable to navigate to xref field at " + Long.toHexString(addrOffset),
			cb.goToField(addr(addrOffset), XRefFieldFactory.FIELD_NAME, 1, 1));
	}

	private void goToXrefHeaderField(int addrOffset) {
		assertTrue("Unable to navigate to xref header field at " + Long.toHexString(addrOffset),
			cb.goToField(addr(addrOffset), XRefHeaderFieldFactory.XREF_FIELD_NAME, 1, 1));
	}

	private void goToXrefField(int addrOffset, String text) {

		// is there a better way to find a field when given an address and some text?

		assertTrue("Unable to navigate to xref field at " + Long.toHexString(addrOffset),
			cb.goToField(addr(addrOffset), XRefFieldFactory.FIELD_NAME, 1, 1));

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		int rows = tf.getNumRows();
		for (int row = 0; row < rows; row++) {

			String rowText = getRowText(tf, row);
			int col = rowText.indexOf(text);
			if (col >= 0) {
				col++; // move past the start position to ensure we are inside of the field
				assertTrue("Unable to navigate to xref field at " + Long.toHexString(addrOffset),
					cb.goToField(addr(addrOffset), XRefFieldFactory.FIELD_NAME, row, col));
				return;
			}
		}

		fail("Uanble to find text at " + Long.toHexString(addrOffset) + "; text: '" + text + "'");
	}

	private String getRowText(ListingTextField tf, int row) {

		List<FieldElement> rowElements = getRowElements(tf, row);
		return StringUtils.join(rowElements);
	}

	private List<FieldElement> getRowElements(ListingTextField tf, int row) {

		List<FieldElement> elements = new ArrayList<>();
		int cols = tf.getNumCols(row);
		for (int col = 0; col < cols; col++) {
			FieldElement element = tf.getFieldElement(row, col);
			if (!elements.contains(element)) {
				elements.add(element);
			}
		}
		return elements;
	}

	private boolean hasXrefField(int addrOffset) {
		return cb.goToField(addr(addrOffset), XRefFieldFactory.FIELD_NAME, 1, 1);
	}

	private Function function(int addr) throws Exception {
		return ensureFunction(addr);
	}

	private Function caller(int addr) throws Exception {
		String name = "callerFunction" + (++callerCount);
		return ensureFunction(addr, name);
	}

	private Function ensureFunction(long from) throws Exception {
		ProgramDB p = builder.getProgram();
		FunctionManager fm = p.getFunctionManager();
		Function f = fm.getFunctionAt(addr(from));
		if (f != null) {
			return f;
		}

		String a = Long.toHexString(from);
		return ensureFunction(from, "Function_" + a);
	}

	private Function ensureFunction(long from, String name) throws Exception {
		ProgramDB p = builder.getProgram();
		FunctionManager fm = p.getFunctionManager();
		Function f = fm.getFunctionAt(addr(from));
		if (f != null) {
			return f;
		}

		String a = Long.toHexString(from);
		return builder.createEmptyFunction(name, "0x" + a, 500, DataType.DEFAULT);
	}

	// creates n references from within caller to the given address
	private void createCallerReference(int toAddr, Function caller, int n) {
		int addr = (int) caller.getEntryPoint().getOffset();
		createMemoryReferencesReference(toAddr, addr, n);
	}

	// create call reference to the given address
	private void createNonFunctionReferences(int toAddr, int fromAddrRangeStart, int n) {
		createMemoryReferencesReference(toAddr, fromAddrRangeStart, n);
	}

	private void createMemoryReferencesReference(int toAddr, int fromAddrRangeStart, int n) {

		int offset = 4;
		int addr = fromAddrRangeStart;
		for (int i = 0; i < n; i++) {
			addr += offset;
			createReference(addr, toAddr);
		}
	}

	private boolean createReference(long from, long to) {
		ProgramDB p = builder.getProgram();
		ReferenceManager rm = p.getReferenceManager();
		Reference existing = rm.getReference(addr(from), addr(to), 0);
		if (existing != null) {
			return false;
		}

		builder.createMemoryCallReference("0x" + Long.toHexString(from),
			"0x" + Long.toHexString(to));
		return true;
	}

	private Address addr(long addr) {
		return builder.addr(addr);
	}

	private void setGroupByFunctionOption(boolean b) {
		setBooleanOption(XRefFieldFactory.GROUP_BY_FUNCTION_KEY, b);
	}

	private void setMaxXrefs(int n) {
		setIntOptions(XRefFieldFactory.MAX_XREFS_KEY, n);
	}

	private void setBooleanOption(String name, boolean value) {

		assertTrue("No such option '" + name + "'", fieldOptions.contains(name));

		runSwing(() -> fieldOptions.setBoolean(name, value));
		waitForSwing();
		cb.updateNow();
	}

	private void setIntOptions(String name, int value) {
		assertTrue("No such option '" + name + "'", fieldOptions.contains(name));

		runSwing(() -> fieldOptions.setInt(name, value));
		waitForSwing();
		cb.updateNow();
	}

}
