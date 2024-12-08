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
package ghidra.features.base.codecompare.model;

import static ghidra.util.datastruct.Duo.Side.*;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.services.FunctionComparisonService;
import ghidra.features.base.codecompare.model.AnyToAnyFunctionComparisonModel;
import ghidra.features.base.codecompare.model.FunctionComparisonModelListener;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.datastruct.Duo.Side;

/**
 * Tests the comparison API for using default function comparison model. Each test verifies that
 * the underlying data model looks correct following a particular API method 
 * call. There are a few tests that also exercise various features of the data
 * model directly.
 * <ul>
 * <li>The API methods being tested: {@link FunctionComparisonService}</li>
 * <li>The model being used for verification: {@link AnyToAnyFunctionComparisonModel}</li>
 * </ul>
 */
public class AnyToAnyFunctionComparisonModelTest extends AbstractGhidraHeadedIntegrationTest {

	private Program program1;
	private Program program2;
	private Function a1;
	private Function a2;
	private Function a3;
	private Function b1;
	private Function b2;
	private Function b3;
	private AnyToAnyFunctionComparisonModel model;

	@Before
	public void setUp() throws Exception {
		buildTestProgram1();
		buildTestProgram2();

		model = createTestModel();
	}

	@Test
	public void testSetNoFunctions() throws Exception {
		model = new AnyToAnyFunctionComparisonModel(new HashSet<>());
		assertTrue(model.isEmpty());
		assertEquals(0, model.getFunctions(LEFT).size());
		assertEquals(0, model.getFunctions(RIGHT).size());
		assertNull(model.getActiveFunction(LEFT));
		assertNull(model.getActiveFunction(RIGHT));
	}

	@Test
	public void testSetOneFunctions() throws Exception {
		Set<Function> set = Set.of(b1);
		model = new AnyToAnyFunctionComparisonModel(set);

		assertFalse(model.isEmpty());
		assertEquals(List.of(b1), model.getFunctions(LEFT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));
		assertEquals(b1, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));
	}

	@Test
	public void testPairOfFunctions() throws Exception {
		Set<Function> set = Set.of(b1, b2);
		model = new AnyToAnyFunctionComparisonModel(set);

		assertEquals(List.of(b1, b2), model.getFunctions(LEFT));
		assertEquals(List.of(b1, b2), model.getFunctions(RIGHT));
		assertEquals(b1, model.getActiveFunction(LEFT));
		assertEquals(b2, model.getActiveFunction(RIGHT));
	}

	@Test
	public void testMultipleFunctions() throws Exception {
		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(LEFT));
		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(RIGHT));
		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(a2, model.getActiveFunction(RIGHT));
	}

	@Test
	public void testDeleteFunction() {

		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(LEFT));
		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(RIGHT));
		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(a2, model.getActiveFunction(RIGHT));

		model.removeFunction(a1);

		assertEquals(List.of(a2, b1, b2), model.getFunctions(LEFT));
		assertEquals(List.of(a2, b1, b2), model.getFunctions(RIGHT));
		assertEquals(a2, model.getActiveFunction(LEFT));
		assertEquals(a2, model.getActiveFunction(RIGHT));
	}

	@Test
	public void testDeleteFunctions() {

		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(LEFT));
		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(RIGHT));
		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(a2, model.getActiveFunction(RIGHT));

		model.removeFunctions(Set.of(a1, b1));

		assertEquals(List.of(a2, b2), model.getFunctions(LEFT));
		assertEquals(List.of(a2, b2), model.getFunctions(RIGHT));
		assertEquals(a2, model.getActiveFunction(LEFT));
		assertEquals(a2, model.getActiveFunction(RIGHT));
	}

	@Test
	public void testDeleteFunctionsForProgram() {

		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(LEFT));
		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(RIGHT));
		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(a2, model.getActiveFunction(RIGHT));

		model.removeFunctions(program2);

		assertEquals(List.of(a1, a2), model.getFunctions(LEFT));
		assertEquals(List.of(a1, a2), model.getFunctions(RIGHT));
		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(a2, model.getActiveFunction(RIGHT));
	}

	@Test
	public void testAddFunctions() {

		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(LEFT));
		assertEquals(List.of(a1, a2, b1, b2), model.getFunctions(RIGHT));
		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(a2, model.getActiveFunction(RIGHT));

		model.addFunctions(Set.of(a3, b3));

		assertEquals(List.of(a1, a2, a3, b1, b2, b3), model.getFunctions(LEFT));
		assertEquals(List.of(a1, a2, a3, b1, b2, b3), model.getFunctions(RIGHT));
		assertEquals(a1, model.getActiveFunction(LEFT));
		// check that one of the new function is now shown on the right -the exact one is random
		assertTrue(Set.of(a3, b3).contains(model.getActiveFunction(RIGHT)));
	}

	@Test
	public void testModelListenerDataChangedWhenFunctionAdded() {
		TestFunctionComparisonModelListener listener = new TestFunctionComparisonModelListener();
		model.addFunctionComparisonModelListener(listener);

		assertFalse(listener.modelDataChanged);
		model.addFunction(a3);
		assertTrue(listener.modelDataChanged);
	}

	@Test
	public void testModelListenerDataChangedWhenFunctionRemoved() {
		TestFunctionComparisonModelListener listener = new TestFunctionComparisonModelListener();
		model.addFunctionComparisonModelListener(listener);

		assertFalse(listener.modelDataChanged);
		model.removeFunction(a1);
		assertTrue(listener.modelDataChanged);
	}

	@Test
	public void testModelListenerDataChangedWhenNonContainingFunctionRemoved() {
		TestFunctionComparisonModelListener listener = new TestFunctionComparisonModelListener();
		model.addFunctionComparisonModelListener(listener);

		assertFalse(listener.modelDataChanged);
		model.removeFunction(a3);
		assertFalse(listener.modelDataChanged);
	}

	@Test
	public void testModelListenerActiveFunctionChanged() {
		TestFunctionComparisonModelListener listener = new TestFunctionComparisonModelListener();
		model.addFunctionComparisonModelListener(listener);

		model.setActiveFunction(LEFT, a2);
		assertEquals(LEFT, listener.changedFunctionSide);
		assertEquals(a2, listener.changedFunction);

		model.setActiveFunction(RIGHT, b1);
		assertEquals(RIGHT, listener.changedFunctionSide);
		assertEquals(b1, listener.changedFunction);

	}

	@Test
	public void testModelListenerActiveFunctionDidNotChanged() {
		TestFunctionComparisonModelListener listener = new TestFunctionComparisonModelListener();
		model.addFunctionComparisonModelListener(listener);

		assertEquals(a1, model.getActiveFunction(LEFT));
		model.setActiveFunction(LEFT, a1);
		assertNull(listener.changedFunctionSide);
		assertNull(listener.changedFunction);

		assertEquals(a2, model.getActiveFunction(RIGHT));
		model.setActiveFunction(RIGHT, a2);
		assertNull(listener.changedFunctionSide);
		assertNull(listener.changedFunction);

	}

	@Test
	public void testSettingBadFunctionActive() {
		Set<Function> set = Set.of(a1, b1);
		model = new AnyToAnyFunctionComparisonModel(set);

		assertEquals(a1, model.getActiveFunction(LEFT));
		model.setActiveFunction(LEFT, a3);
		assertEquals(a1, model.getActiveFunction(LEFT));

		assertEquals(b1, model.getActiveFunction(RIGHT));
		model.setActiveFunction(RIGHT, b2);
		assertEquals(b1, model.getActiveFunction(RIGHT));
	}

	private ProgramBuilder buildTestProgram1() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestPgm1", ProgramBuilder._TOY_BE);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		// functions 
		DataType dt = new ByteDataType();
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		a1 = builder.createEmptyFunction("A1", "10018cf", 10, null, p);
		a2 = builder.createEmptyFunction("A2", "100299e", 130, null, p, p, p);
		a3 = builder.createEmptyFunction("A3", "1002cf5", 15, null, p, p, p, p, p);

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
		b1 = builder.createEmptyFunction("B1", "10017c5", 10, null, p);
		b2 = builder.createEmptyFunction("B2", "1001822", 130, null, p, p, p);
		b3 = builder.createEmptyFunction("B3", "1001944", 15, null, p, p, p, p, p);

		program2 = builder.getProgram();
		AbstractGenericTest.setInstanceField("recordChanges", program2, Boolean.TRUE);
		return builder;
	}

	private AnyToAnyFunctionComparisonModel createTestModel() {
		Set<Function> set = Set.of(b1, b2, a1, a2);
		return new AnyToAnyFunctionComparisonModel(set);
	}

	private class TestFunctionComparisonModelListener implements FunctionComparisonModelListener {
		boolean modelDataChanged = false;
		Side changedFunctionSide = null;
		Function changedFunction = null;

		@Override
		public void activeFunctionChanged(Side side, Function function) {
			changedFunctionSide = side;
			changedFunction = function;
		}

		@Override
		public void modelDataChanged() {
			modelDataChanged = true;
		}
	}
}
