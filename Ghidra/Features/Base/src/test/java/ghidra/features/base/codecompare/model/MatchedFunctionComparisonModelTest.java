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

import java.util.Date;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.services.FunctionComparisonService;
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
 * <li>The API methods being tested: {@link FunctionComparisonService}</li>
 * <li>The model being used for verification: {@link AnyToAnyFunctionComparisonModel}</li>
 */
public class MatchedFunctionComparisonModelTest extends AbstractGhidraHeadedIntegrationTest {

	private Program program1;
	private Program program2;
	private Function a1;
	private Function a2;
	private Function a3;
	private Function a4;
	private Function b1;
	private Function b2;
	private Function b3;
	private Function b4;
	private MatchedFunctionComparisonModel model;

	@Before
	public void setUp() throws Exception {
		buildTestProgram1();
		buildTestProgram2();

		model = createTestModel();
	}

	@Test
	public void testSetNoFunctions() throws Exception {
		model = new MatchedFunctionComparisonModel();
		assertTrue(model.isEmpty());
		assertEquals(0, model.getFunctions(LEFT).size());
		assertEquals(0, model.getFunctions(RIGHT).size());
		assertNull(model.getActiveFunction(LEFT));
		assertNull(model.getActiveFunction(RIGHT));
	}

	@Test
	public void testPairOfFunctions() throws Exception {
		model = new MatchedFunctionComparisonModel();
		model.addMatch(a1, b1);

		assertEquals(List.of(a1), model.getFunctions(LEFT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));
		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));
	}

	@Test
	public void testMultipleFunctions() throws Exception {
		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));

		assertEquals(a3, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		assertEquals(List.of(b1), model.getFunctions(RIGHT));

		model.setActiveFunction(LEFT, a1);
		assertEquals(List.of(b1, b2), model.getFunctions(RIGHT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		model.setActiveFunction(LEFT, a2);
		assertEquals(List.of(b2, b3), model.getFunctions(RIGHT));
		assertEquals(b2, model.getActiveFunction(RIGHT));

		model.setActiveFunction(LEFT, a3);
		assertEquals(List.of(b1), model.getFunctions(RIGHT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));

	}

	@Test
	public void testDeleteSourceFunctionActive() {
		assertEquals(a3, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));

		model.removeFunction(a3);

		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		assertEquals(List.of(a1, a2), model.getFunctions(LEFT));
		assertEquals(List.of(b1, b2), model.getFunctions(RIGHT));
	}

	@Test
	public void testDeleteSourceFunctionNonActive() {
		assertEquals(a3, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));

		model.removeFunction(a1);

		assertEquals(a3, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		assertEquals(List.of(a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));
	}

	@Test
	public void testDeleteTargetFunctionActive() {
		model.setActiveFunction(LEFT, a1);
		model.setActiveFunction(RIGHT, b2);

		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(b2, model.getActiveFunction(RIGHT));

		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b1, b2), model.getFunctions(RIGHT));

		model.removeFunction(b2);

		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));
	}

	@Test
	public void testDeleteSingleTargetFromActive() {
		model.setActiveFunction(LEFT, a3);
		model.setActiveFunction(RIGHT, b1);

		assertEquals(a3, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));

		model.removeFunction(b1);

		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(b2, model.getActiveFunction(RIGHT));

		assertEquals(List.of(a1, a2), model.getFunctions(LEFT));
		assertEquals(List.of(b2), model.getFunctions(RIGHT));
	}

	@Test
	public void testDeleteSingleTargetDeletesSourceAsWell() {
		model.setActiveFunction(LEFT, a1);
		model.setActiveFunction(RIGHT, b2);

		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(b2, model.getActiveFunction(RIGHT));

		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b1, b2), model.getFunctions(RIGHT));

		model.removeFunction(b1);

		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(b2, model.getActiveFunction(RIGHT));

		// note a3 was removed because it only had one target, b1, which was deleted
		assertEquals(List.of(a1, a2), model.getFunctions(LEFT));
		assertEquals(List.of(b2), model.getFunctions(RIGHT));
	}

	@Test
	public void testDeleteFunctionsForDestinationProgram() {

		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));
		assertEquals(a3, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		// this will delete everything because all the sources have no targets
		model.removeFunctions(program2);

		assertEquals(List.of(), model.getFunctions(LEFT));
		assertEquals(List.of(), model.getFunctions(RIGHT));
		assertNull(model.getActiveFunction(LEFT));
		assertNull(model.getActiveFunction(RIGHT));
	}

	@Test
	public void testDeleteFunctionsForSourceProgram() {

		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b1), model.getFunctions(RIGHT));
		assertEquals(a3, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		// this will delete everything because all the sources have no targets
		model.removeFunctions(program1);

		assertEquals(List.of(), model.getFunctions(LEFT));
		assertEquals(List.of(), model.getFunctions(RIGHT));
		assertNull(model.getActiveFunction(LEFT));
		assertNull(model.getActiveFunction(RIGHT));
	}

	@Test
	public void testAddTotallyNewMatch() {

		model.addMatch(a4, b4);

		assertEquals(List.of(a1, a2, a3, a4), model.getFunctions(LEFT));
		assertEquals(List.of(b4), model.getFunctions(RIGHT));
		assertEquals(a4, model.getActiveFunction(LEFT));
		assertEquals(b4, model.getActiveFunction(RIGHT));
	}

	@Test
	public void testAddToExistingMatch() {

		model.addMatch(a2, b4);

		assertEquals(List.of(a1, a2, a3), model.getFunctions(LEFT));
		assertEquals(List.of(b2, b3, b4), model.getFunctions(RIGHT));
		assertEquals(a2, model.getActiveFunction(LEFT));
		assertEquals(b4, model.getActiveFunction(RIGHT));
	}

	@Test
	public void testModelListenerDataChangedWhenFunctionAdded() {
		TestFunctionComparisonModelListener listener = new TestFunctionComparisonModelListener();
		model.addFunctionComparisonModelListener(listener);

		assertFalse(listener.modelDataChanged);
		model.addMatch(a1, b4);
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
		model.removeFunction(a4);
		assertFalse(listener.modelDataChanged);
	}

	@Test
	public void testRightSideModelListenerActiveFunctionChanged() {
		model.setActiveFunction(LEFT, a1);
		model.setActiveFunction(RIGHT, b1);
		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		TestFunctionComparisonModelListener listener = new TestFunctionComparisonModelListener();
		model.addFunctionComparisonModelListener(listener);

		model.setActiveFunction(RIGHT, b2);
		assertEquals(RIGHT, listener.changedFunctionSide);
		assertEquals(b2, listener.changedFunction);

		model.setActiveFunction(RIGHT, b1);
		assertEquals(RIGHT, listener.changedFunctionSide);
		assertEquals(b1, listener.changedFunction);
	}

	@Test
	public void testLeftSideModelListenerActiveFunctionChanged() {
		model.setActiveFunction(LEFT, a1);
		model.setActiveFunction(RIGHT, b1);
		assertEquals(a1, model.getActiveFunction(LEFT));
		assertEquals(b1, model.getActiveFunction(RIGHT));

		TestFunctionComparisonModelListener listener = new TestFunctionComparisonModelListener();
		model.addFunctionComparisonModelListener(listener);

		model.setActiveFunction(LEFT, a2);
		assertTrue(listener.modelDataChanged);
	}

	@Test
	public void testModelListenerActiveFunctionDidNotChanged() {
		model.setActiveFunction(LEFT, a1);
		model.setActiveFunction(RIGHT, b1);

		TestFunctionComparisonModelListener listener = new TestFunctionComparisonModelListener();
		model.addFunctionComparisonModelListener(listener);

		assertEquals(a1, model.getActiveFunction(LEFT));
		model.setActiveFunction(LEFT, a1);
		assertNull(listener.changedFunctionSide);
		assertNull(listener.changedFunction);

		assertEquals(b1, model.getActiveFunction(RIGHT));
		model.setActiveFunction(RIGHT, b1);
		assertNull(listener.changedFunctionSide);
		assertNull(listener.changedFunction);

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
		a4 = builder.createEmptyFunction("A4", "1003100", 20, null, p, p);

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
		b4 = builder.createEmptyFunction("B4", "1002100", 20, null, p, p);

		program2 = builder.getProgram();
		AbstractGenericTest.setInstanceField("recordChanges", program2, Boolean.TRUE);
		return builder;
	}

	private MatchedFunctionComparisonModel createTestModel() {
		MatchedFunctionComparisonModel m = new MatchedFunctionComparisonModel();
		m.addMatch(a1, b1);
		m.addMatch(a1, b2);
		m.addMatch(a2, b2);
		m.addMatch(a2, b3);
		m.addMatch(a3, b1);
		return m;
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
