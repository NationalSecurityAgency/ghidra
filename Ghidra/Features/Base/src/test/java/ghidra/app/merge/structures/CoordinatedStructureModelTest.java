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
package ghidra.app.merge.structures;

import static ghidra.app.merge.structures.CoordinatedStructureModelTest.ApplyState.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.function.Consumer;

import org.junit.Before;
import org.junit.Test;

import docking.DockingWindowManager;
import ghidra.program.database.data.merge.StructureBuilder;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.UniversalIdGenerator;
import utility.function.Dummy;

public class CoordinatedStructureModelTest extends AbstractGhidraHeadedIntegrationTest {
	enum ApplyState {
		YES, NO, NA
	}

	private DataType wordDt;
	private DataType dwordDt;
	private IntegerDataType intDt;
	private DataType zeroArrayDt;
	private Consumer<String> errorHandler;
	private CoordinatedStructureModel model;
	private Structure struct1;
	private Structure struct2;

	@Before
	public void setUp() throws Exception {
		UniversalIdGenerator.initialize();
		wordDt = new WordDataType();
		dwordDt = new DWordDataType();
		intDt = new IntegerDataType();
		zeroArrayDt = new ArrayDataType(intDt, 0);
		this.errorHandler = e -> reportError(e);
	}

	@Test
	public void testStructName() {
		struct1 = new StructureBuilder("A", 8)
				.build();

		struct2 = new StructureBuilder("B", 8)
				.build();

		createModel();

		assertLeft(0, "Struct A");
		assertRight(0, "Struct B");
		assertResult(0, "Struct A");

		assertAppliable(0, NO, YES);

		applyRight(0);
		assertResult(0, "Struct B");
		assertAppliable(0, YES, NO);

		applyLeft(0);
		assertResult(0, "Struct A");
		assertAppliable(0, NO, YES);
	}

	private void createModel() {
		model = new CoordinatedStructureModel(struct1, struct2, errorHandler);

		// un-comment the following line out to show the dialog for for debugging purposes
		// showDialog();
	}

	@Test
	public void testStructDescription() {
		struct1 = new StructureBuilder("A", 8)
				.description("Comment A")
				.build();

		struct2 = new StructureBuilder("B", 8)
				.description("Comment B")
				.build();
		createModel();

		assertLeft(0, "// Comment A");
		assertRight(0, "// Comment B");
		assertResult(0, "// Comment A");
		assertAppliable(0, NO, YES);

		applyRight(0);
		assertResult(0, "// Comment B");
		assertAppliable(0, YES, NO);

		applyLeft(0);
		assertResult(0, "// Comment A");
		assertAppliable(0, NO, YES);
	}

	@Test
	public void testStructDescriptionOneSideBlank() {
		struct1 = new StructureBuilder("A", 8)
				.build();

		struct2 = new StructureBuilder("B", 8)
				.description("Comment B")
				.build();
		createModel();

		assertLeft(0, "");
		assertRight(0, "// Comment B");
		assertResult(0, "// Comment B");
		assertAppliable(0, YES, NO);

		applyLeft(0);
		assertResult(0, "");
		assertAppliable(0, NO, YES);

		applyRight(0);
		assertResult(0, "// Comment B");
		assertAppliable(0, YES, NO);
	}

	@Test
	public void testComponentSameOffsetDatatypesDiffer() {
		struct1 = new StructureBuilder("A", 10)
				.add(0, intDt, "aaa")
				.build();

		struct2 = new StructureBuilder("B", 10)
				.add(0, wordDt, "xxx")
				.build();
		createModel();

		assertLeft(3, "0 int aaa");
		assertRight(3, "0 word xxx");
		assertResult(3, "0 int aaa");

		assertAppliable(3, NO, YES);

		applyRight(3);
		assertLeft(3, "0 int aaa");
		assertRight(3, "0 word xxx");
		assertResult(3, "0 word xxx");

		assertAppliable(3, YES, NO);

		applyLeft(3);
		assertLeft(3, "0 int aaa");
		assertRight(3, "0 word xxx");
		assertResult(3, "0 int aaa");
	}

	@Test
	public void testComponentSameOffsetOnlyNameDiffers() {
		struct1 = new StructureBuilder("A", 8)
				.add(0, intDt, "foo")
				.build();

		struct2 = new StructureBuilder("B", 8)
				.add(0, intDt, "bar")
				.build();
		createModel();

		// line 0 is struct name
		// line 1 is struct size, alignment and packing
		// line 2 is {
		// line 3 is component line

		assertLeft(3, "0 int foo");
		assertRight(3, "0 int bar");
		assertResult(3, "0 int foo");

		assertAppliable(3, NO, YES);

		applyRight(3);
		assertResult(3, "0 int bar");
		assertAppliable(3, YES, NO);

		applyLeft(3);
		assertResult(3, "0 int foo");
		assertAppliable(3, NO, YES);
	}

	@Test
	public void testOtherTypeApplieNoName() {
		struct1 = new StructureBuilder("A", 8)
				.build();

		struct2 = new StructureBuilder("B", 8)
				.add(0, intDt, null)
				.build();
		createModel();

		assertLeft(3, "0 undefined (4)");
		assertRight(3, "0 int");
		assertResult(3, "0 int");

		assertAppliable(3, NA, NO);

		clearRight(3);
		assertResult(3, "0 undefined (4)");
		assertAppliable(3, NA, YES);

		applyRight(3);
		assertResult(3, "0 int");
		assertAppliable(3, NA, NO);
	}

	@Test
	public void testComponentSameOffsetOnlyCommentDiffers() {
		struct1 = new StructureBuilder("A", 8)
				.add(0, intDt, "foo", "aaa")
				.build();

		struct2 = new StructureBuilder("B", 8)
				.add(0, intDt, "foo", "bbb")
				.build();
		createModel();

		// line 0 is struct name
		// line 1 is struct size, alignment and packing
		// line 2 is {
		// line 3 is component line

		assertLeft(3, "0 int foo // aaa");
		assertRight(3, "0 int foo // bbb");
		assertResult(3, "0 int foo // aaa");

		assertAppliable(3, NO, YES);

		applyRight(3);
		assertResult(3, "0 int foo // bbb");
		assertAppliable(3, YES, NO);

		applyLeft(3);
		assertResult(3, "0 int foo // aaa");
		assertAppliable(3, NO, YES);
	}

	@Test
	public void testComponentSameOffsetDifferentNameRightAddsComment() {
		struct1 = new StructureBuilder("A", 8)
				.add(0, intDt, "foo")
				.build();

		struct2 = new StructureBuilder("B", 8)
				.add(0, intDt, "bar", "bbb")
				.build();
		createModel();

		// line 0 is struct name
		// line 1 is struct size, alignment and packing
		// line 2 is {
		// line 3 is component line

		assertLeft(3, "0 int foo");
		assertRight(3, "0 int bar // bbb");
		assertResult(3, "0 int foo // bbb");

		assertAppliable(3, YES, YES);

		applyRight(3);
		assertResult(3, "0 int bar // bbb");
		assertAppliable(3, YES, NO);

		applyLeft(3);
		assertResult(3, "0 int foo");
		assertAppliable(3, NO, YES);
	}

	@Test
	public void testComponentOffcut() {
		struct1 = new StructureBuilder("A", 10)
				.add(0, intDt, "aaa")
				.add(4, intDt, "bbb")
				.build();

		struct2 = new StructureBuilder("B", 10)
				.add(1, intDt, "xxx")
				.add(5, intDt, "yyy")
				.build();
		createModel();

		assertLeft(3, "0 int aaa");
		assertLeft(4, "");
		assertLeft(5, "4 int bbb");
		assertLeft(6, "");

		assertRight(3, "0 undefined (1)");
		assertRight(4, "1 int xxx");
		assertRight(5, "");
		assertRight(6, "5 int yyy");

		assertResult(3, "0 int aaa");
		assertResult(4, "");
		assertResult(5, "4 int bbb");
		assertResult(6, "");

		assertAppliable(3, NO, NA);
		assertAppliable(4, NA, YES);
		assertAppliable(5, NO, NA);
		assertAppliable(6, NA, YES);

		// apply right side on line 4, line 3 and 5 that are defined on the left side are cleared
		applyRight(4);

		assertResult(3, "0 undefined (1)");
		assertResult(4, "1 int xxx");
		assertResult(5, "");
		assertResult(6, "5 undefined (4)");

		assertAppliable(3, YES, NA);
		assertAppliable(4, NA, NO);
		assertAppliable(5, YES, NA);
		assertAppliable(6, NA, YES);

	}

	@Test
	public void testZeroSizedArrays() {
		struct1 = new StructureBuilder("A", 8)
				.add(0, dwordDt, "foo", "comment")
				.build();

		struct2 = new StructureBuilder("B", 8)
				.add(0, zeroArrayDt, "arrayX")
				.add(0, zeroArrayDt, "arrayY")
				.add(0, zeroArrayDt, "arrayZ")
				.build();
		createModel();

		assertLeft(3, "");
		assertLeft(4, "");
		assertLeft(5, "");
		assertLeft(6, "0 dword foo // comment");

		assertRight(3, "0 int[0] arrayX");
		assertRight(4, "0 int[0] arrayY");
		assertRight(5, "0 int[0] arrayZ");
		assertRight(6, "0 undefined (4)");

		assertResult(3, "0 int[0] arrayX");
		assertResult(4, "0 int[0] arrayY");
		assertResult(5, "0 int[0] arrayZ");
		assertResult(6, "0 dword foo // comment");

		assertAppliable(3, NA, NO);
		assertAppliable(4, NA, NO);
		assertAppliable(5, NA, NO);
		assertAppliable(6, NO, NA);

	}

	@Test
	public void testBitFieldNoConflicts() throws Exception {
		struct1 = new StructureBuilder("A", 10)
				.bitField(0, 1, 0, 2, "A")
				.bitField(0, 1, 5, 6, "B")
				.build();

		struct2 = new StructureBuilder("B", 10)
				.bitField(0, 1, 3, 4, "C")
				.bitField(0, 1, 7, 7, "D")
				.build();
		createModel();

		assertLeft(3, "0 int:3 (0, 2) A");
		assertLeft(4, "");
		assertLeft(5, "0 int:2 (5, 6) B");
		assertLeft(6, "");

		assertRight(3, "");
		assertRight(4, "0 int:2 (3, 4) C");
		assertRight(5, "");
		assertRight(6, "0 int:1 (7, 7) D");

		assertResult(3, "0 int:3 (0, 2) A");
		assertResult(4, "0 int:2 (3, 4) C");
		assertResult(5, "0 int:2 (5, 6) B");
		assertResult(6, "0 int:1 (7, 7) D");

		assertAppliable(3, NO, NA);
		assertAppliable(4, NA, NO);
		assertAppliable(5, NO, NA);
		assertAppliable(6, NA, NO);

	}

	@Test
	public void testBitFieldConflicts() throws Exception {
		struct1 = new StructureBuilder("A", 10)
				.bitField(0, 1, 0, 2, "A")
				.bitField(0, 1, 5, 6, "B")
				.build();

		struct2 = new StructureBuilder("B", 10)
				.bitField(0, 1, 2, 7, "C")
				.build();
		createModel();

		assertLeft(3, "0 int:3 (0, 2) A");
		assertLeft(4, "");
		assertLeft(5, "0 int:2 (5, 6) B");

		assertRight(3, "");
		assertRight(4, "0 int:6 (2, 7) C");
		assertRight(5, "");

		assertResult(3, "0 int:3 (0, 2) A");
		assertResult(4, "");
		assertResult(5, "0 int:2 (5, 6) B");

		assertAppliable(3, NO, NA);
		assertAppliable(4, NA, YES);
		assertAppliable(5, NO, NA);

		applyRight(4);

		assertResult(3, "");
		assertResult(4, "0 int:6 (2, 7) C");
		assertResult(5, "");

		assertAppliable(3, YES, NA);
		assertAppliable(4, NA, NO);
		assertAppliable(5, YES, NA);

	}

	@Test
	public void testBitFieldConflictWithNonBitField() throws Exception {
		struct1 = new StructureBuilder("A", 10)
				.bitField(0, 2, 5, 12, "A")
				.build();

		struct2 = new StructureBuilder("B", 10)
				.add(1, intDt, "B")
				.build();
		createModel();

		assertLeft(3, "0 int:8 (5, 12) A");
		assertLeft(4, "");

		assertRight(3, "0 undefined (1)");
		assertRight(4, "1 int B");

		assertResult(3, "0 int:8 (5, 12) A");
		assertResult(4, "");

		assertAppliable(3, NO, NA);
		assertAppliable(4, NA, YES);

		applyRight(4);

		assertResult(3, "0 undefined (1)");
		assertResult(4, "1 int B");

		assertAppliable(3, YES, NA);
		assertAppliable(4, NA, NO);

	}

	@Test
	public void testBitFieldInteractsWithZeroLengthArrays() throws Exception {
		struct1 = new StructureBuilder("A", 10)
				.bitField(0, 2, 5, 12, "A")
				.build();

		struct2 = new StructureBuilder("B", 10)
				.add(0, zeroArrayDt, "B")
				.add(0, zeroArrayDt, "C")
				.build();
		createModel();

		assertLeft(3, "");
		assertLeft(4, "");
		assertLeft(5, "0 int:8 (5, 12) A");

		assertRight(3, "0 int[0] B");
		assertRight(4, "0 int[0] C");
		assertRight(5, "0 undefined (2)");

		assertResult(3, "0 int[0] B");
		assertResult(4, "0 int[0] C");
		assertResult(5, "0 int:8 (5, 12) A");

		assertAppliable(3, NA, NO);
		assertAppliable(4, NA, NO);
		assertAppliable(5, NO, NA);
	}

	@Test
	public void testBitFieldCommentDiffs() throws Exception {
		struct1 = new StructureBuilder("A", 10)
				.bitField(0, 2, 5, 12, "A", "Comment A")
				.build();

		struct2 = new StructureBuilder("B", 10)
				.bitField(0, 2, 5, 12, "A", "Comment B")
				.build();
		createModel();

		assertLeft(3, "0 int:8 (5, 12) A // Comment A");
		assertRight(3, "0 int:8 (5, 12) A // Comment B");
		assertResult(3, "0 int:8 (5, 12) A // Comment A");

		assertAppliable(3, NO, YES);

		applyRight(3);
		assertResult(3, "0 int:8 (5, 12) A // Comment B");
	}

	@Test
	public void testClear() throws Exception {
		struct1 = new StructureBuilder("A", 10)
				.add(0, intDt, "aaa")
				.build();

		struct2 = new StructureBuilder("B", 10)
				.add(0, wordDt, "xxx")
				.build();
		createModel();

		assertLeft(3, "0 int aaa");
		assertRight(3, "0 word xxx");
		assertResult(3, "0 int aaa");

		assertAppliable(3, NO, YES);
		clearLeft(3);
		assertResult(3, "0 undefined (4)");
		applyRight(3);
		assertResult(3, "0 word xxx");
		clearRight(3);
		assertResult(3, "0 undefined (4)");

	}

	private void assertAppliable(int line, ApplyState left, ApplyState right) {
		CoordinatedStructureLine compareLine = model.getLines().get(line);
		assertAppliable("Left", line, compareLine.left, left);
		assertAppliable("Right", line, compareLine.right, right);
	}

	private void assertAppliable(String side, int line, ComparisonItem item,
			ApplyState expectedState) {
		boolean appliable = item.isAppliable();

		if (!appliable) {
			if (expectedState != NA) {
				fail("Expected %s side at line %d to be %s, but was NA".formatted(side, line,
					expectedState));

			}
		}
		else {
			if (appliable && expectedState == NA) {
				fail("Expected %s side at line %d to be NA, but was %s".formatted(side, line,
					expectedState));
			}
			ApplyState state = item.canApplyAny() ? YES : NO;
			assertEquals("Incorrect apply state on %s side at line %d".formatted(side, line),
				expectedState, state);
		}
	}

	private void applyRight(int line) {
		ComparisonItem right = extracted(line);
		right.applyAll();
	}

	private ComparisonItem extracted(int line) {
		CoordinatedStructureLine compareLine = model.getLines().get(line);
		ComparisonItem right = compareLine.right;
		return right;
	}

	private void applyLeft(int line) {
		CoordinatedStructureLine compareLine = model.getLines().get(line);
		ComparisonItem left = compareLine.left;
		left.applyAll();
	}

	private void clearLeft(int line) {
		CoordinatedStructureLine compareLine = model.getLines().get(line);
		ComparisonItem left = compareLine.left;
		left.clear();
	}

	private void clearRight(int line) {
		CoordinatedStructureLine compareLine = model.getLines().get(line);
		ComparisonItem left = compareLine.left;
		left.clear();
	}

	private void assertLeft(int line, String expected) {
		CoordinatedStructureLine compareLine = model.getLines().get(line);
		assertEquals("Left component at line " + line, expected, compareLine.left.toString());
	}

	private void assertRight(int line, String expected) {
		CoordinatedStructureLine compareLine = model.getLines().get(line);
		assertEquals("Right component at line " + line, expected, compareLine.right.toString());
	}

	private void assertResult(int line, String expected) {
		CoordinatedStructureLine compareLine = model.getLines().get(line);
		assertEquals("Result at line " + line + ": ", expected, compareLine.merged.toString());
	}

	private void reportError(String message) {
		fail("Got unexpected exception: " + message);
	}

	private void showDialog() {
		try {
			TestEnv env = new TestEnv();
			env.showTool();
			StructureMergeDialog dialog = new StructureMergeDialog("Test Merge", struct1, struct2,
				Dummy.exceptionalConsumer());
			DockingWindowManager.showDialog(dialog);
		}
		catch (IOException e) {
			failWithException("Faile to create TestEnv", e);
		}
	}
}
