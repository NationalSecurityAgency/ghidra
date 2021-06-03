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
package ghidra.app.plugin.core.functioncompare;

import static org.junit.Assert.*;

import java.util.Date;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.services.FunctionComparisonModel;
import ghidra.app.services.FunctionComparisonService;
import ghidra.framework.plugintool.DummyPluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * Tests the function comparison API and data model. Each test verifies that
 * the underlying data model looks correct following a particular API method 
 * call. There are a few tests that also exercise various features of the data
 * model directly.
 * <li>The API methods being tested: {@link FunctionComparisonService}</li>
 * <li>The model being used for verification: {@link FunctionComparison}</li>
 */
public class CompareFunctionsTest extends AbstractGhidraHeadedIntegrationTest {

	private Program program1;
	private Program program2;
	private Function foo;
	private Function bar;
	private Function junk;
	private Function stuff;
	private Function one;
	private Function two;
	private Function three;
	private Function four;
	private Function five;
	private FunctionComparisonPlugin plugin;
	private FunctionComparisonProvider provider;
	private FunctionComparisonProvider provider2;
	private FunctionComparisonModel model;

	@Before
	public void setUp() throws Exception {
		DummyPluginTool tool = new DummyPluginTool();
		plugin = new FunctionComparisonPlugin(tool);
		buildTestProgram1();
		buildTestProgram2();

		model = createTestModel();
	}

	@Test
	public void testSetNoFunctions() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet();
		provider = compare(functions);
		assertNull(provider);
	}

	@Test
	public void testSetOneFunction() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo);
		provider = compare(functions);
		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo);
	}

	@Test
	public void testSetDuplicateFunctionDifferentProviders() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo);
		provider = compare(functions);
		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo);

		provider2 = compare(functions);
		CompareFunctionsTestUtility.checkSourceFunctions(provider2, foo);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, foo, foo);
	}

	@Test
	public void testSetDuplicateFunctionSameProvider() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo);
		provider = compare(functions);
		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo);

		compare(functions, provider);
		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo);
	}

	@Test
	public void testSetMultipleFunctions() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, junk, stuff);
		provider = compare(functions);
		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, junk, stuff);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, junk, stuff);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, junk, foo, junk, stuff);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, stuff, foo, junk, stuff);
	}

	@Test
	public void testSetMultipleFunctionsMultipleSets() throws Exception {
		Set<Function> functions1 = CompareFunctionsTestUtility.getFunctionsAsSet(one, two);
		Set<Function> functions2 = CompareFunctionsTestUtility.getFunctionsAsSet(three, four, five);

		provider = compare(functions1);
		provider2 = compare(functions2);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, one, two);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, one, one, two);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, two, one, two);
		CompareFunctionsTestUtility.checkSourceFunctions(provider2, three, four, five);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, three, three, four, five);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, four, three, four, five);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, five, three, four, five);
	}

	@Test
	public void testSetCombineTwoSets() throws Exception {
		Set<Function> functions1 = CompareFunctionsTestUtility.getFunctionsAsSet(foo, two);
		Set<Function> functions2 = CompareFunctionsTestUtility.getFunctionsAsSet(bar, three, four);

		provider = compare(functions1);
		compare(functions2, provider);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, two, bar, three, four);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, two, bar, three, four);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, two, foo, two, bar, three, four);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, foo, two, bar, three, four);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, three, foo, two, bar, three,
			four);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, four, foo, two, bar, three,
			four);
	}

	@Test
	public void testSetAddToSpecificProvider() throws Exception {
		Set<Function> functions1 = CompareFunctionsTestUtility.getFunctionsAsSet(foo, two);
		Set<Function> functions2 = CompareFunctionsTestUtility.getFunctionsAsSet(bar, three);
		Set<Function> functions3 = CompareFunctionsTestUtility.getFunctionsAsSet(four);
		provider = compare(functions1);
		provider2 = compare(functions2);

		compare(functions3, provider2);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, two);
		CompareFunctionsTestUtility.checkSourceFunctions(provider2, bar, three, four);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, two);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, two, foo, two);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, bar, bar, three, four);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, three, bar, three, four);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, four, bar, three, four);
	}

	@Test
	public void testRemoveFunction() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compare(functions);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, foo, bar);

		remove(foo);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, bar);
	}

	@Test
	public void testRemoveFunctionTargetOnly() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compare(functions);

		// add a target to foo, which is not also a source
		runSwing(() -> plugin.compareFunctions(foo, two, provider));

		// Verify the structure with the new target
		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, bar, two);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, foo, bar);

		remove(two);

		// Verify the new target is gone
		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, foo, bar);
	}

	@Test
	public void testRemoveFunctionMultipleProviders() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compare(functions);
		provider2 = compare(functions);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, bar);
		CompareFunctionsTestUtility.checkSourceFunctions(provider2, foo, bar);

		remove(foo);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, bar);
		CompareFunctionsTestUtility.checkSourceFunctions(provider2, bar);
	}

	@Test
	public void testRemoveNonexistentFunction() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compare(functions);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, foo, bar);

		remove(two);  // nothing should happen

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, foo, bar);
	}

	@Test
	public void testRemoveFunctionFromSpecificProvider() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compare(functions);
		provider2 = compare(functions);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, foo, bar);
		CompareFunctionsTestUtility.checkSourceFunctions(provider2, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, foo, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, bar, foo, bar);

		remove(foo, provider);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, bar);
		CompareFunctionsTestUtility.checkSourceFunctions(provider2, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, foo, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider2, bar, foo, bar);
	}

	@Test
	public void testDualCompare() {
		provider = compare(foo, bar);
		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, bar);
	}

	@Test
	public void testDualCompareAddToExisting() {
		provider = compare(foo, bar);
		runSwing(() -> plugin.compareFunctions(foo, two, provider));

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, bar, two);
	}

//==================================================================================================
// Data Model tests
//==================================================================================================	

	@Test
	public void testGetTargets() {
		Set<Function> targets = model.getTargetFunctions();
		assertEquals(6, targets.size());
		assertTrue(targets.contains(bar));
		assertTrue(targets.contains(two));
		assertTrue(targets.contains(three));
		assertTrue(targets.contains(four));
		assertTrue(targets.contains(five));
		assertTrue(targets.contains(stuff));
	}

	@Test
	public void testGetTargetsForSource() {
		Set<Function> targets = model.getTargetFunctions(bar);
		assertEquals(3, targets.size());
		assertTrue(targets.contains(three));
		assertTrue(targets.contains(four));
		assertTrue(targets.contains(five));
	}

	@Test
	public void getSources() {
		Set<Function> sources = model.getSourceFunctions();
		assertEquals(3, sources.size());
		assertTrue(sources.contains(foo));
		assertTrue(sources.contains(bar));
		assertTrue(sources.contains(junk));
	}

	@Test
	public void testRemoveFunctionFromModel() {
		model.removeFunction(bar);

		Set<Function> sources = model.getSourceFunctions();
		assertEquals(2, sources.size());
		assertTrue(sources.contains(foo));
		assertTrue(sources.contains(junk));

		Set<Function> targets = model.getTargetFunctions(foo);
		assertEquals(1, targets.size());
		assertTrue(targets.contains(two));

		targets = model.getTargetFunctions(junk);
		assertEquals(1, targets.size());
		assertTrue(targets.contains(stuff));
	}

	private void remove(Function f) {
		runSwing(() -> plugin.removeFunction(f));
	}

	private void remove(Function f, FunctionComparisonProvider fp) {
		runSwing(() -> plugin.removeFunction(f, fp));
	}

	private void compare(Set<Function> functions, FunctionComparisonProvider fp) {
		runSwing(() -> plugin.compareFunctions(functions, fp));
	}

	private FunctionComparisonProvider compare(Set<Function> functions) {
		return plugin.compareFunctions(functions);
	}

	private FunctionComparisonProvider compare(Function f1, Function f2) {
		return plugin.compareFunctions(f1, f2);
	}

	private ProgramBuilder buildTestProgram1() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestPgm1", ProgramBuilder._TOY_BE);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		// functions 
		DataType dt = new ByteDataType();
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		foo = builder.createEmptyFunction("Foo", "10018cf", 10, null, p);
		bar = builder.createEmptyFunction("Bar", "100299e", 130, null, p, p, p);
		junk = builder.createEmptyFunction("Junk", "1002cf5", 15, null, p, p, p, p, p);
		stuff = builder.createEmptyFunction("Stuff", "1003100", 20, null, p, p);

		program1 = builder.getProgram();
		AbstractGenericTest.setInstanceField("recordChanges", program1, Boolean.TRUE);
		return builder;
	}

	private ProgramBuilder buildTestProgram2() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestPgm2", ProgramBuilder._TOY64_BE);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		// functions 
		DataType dt = new ByteDataType();
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		one = builder.createEmptyFunction("One", "10017c5", 10, null, p);
		two = builder.createEmptyFunction("Two", "1001822", 130, null, p, p, p);
		three = builder.createEmptyFunction("Three", "1001944", 15, null, p, p, p, p, p);
		four = builder.createEmptyFunction("Four", "1002100", 20, null, p, p);
		five = builder.createEmptyFunction("Five", "1002200", 20, null, p, p);

		program2 = builder.getProgram();
		AbstractGenericTest.setInstanceField("recordChanges", program2, Boolean.TRUE);
		return builder;
	}

	private FunctionComparisonModel createTestModel() {
		FunctionComparisonModel newModel = new FunctionComparisonModel();

		FunctionComparison c1 = new FunctionComparison();
		c1.setSource(foo);
		c1.addTarget(bar);
		c1.addTarget(two);
		newModel.addComparison(c1);

		FunctionComparison c2 = new FunctionComparison();
		c2.setSource(bar);
		c2.addTarget(three);
		c2.addTarget(four);
		c2.addTarget(five);
		newModel.addComparison(c2);

		FunctionComparison c3 = new FunctionComparison();
		c3.setSource(junk);
		c3.addTarget(stuff);
		newModel.addComparison(c3);

		return newModel;
	}
}
