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
package ghidra.app.util.html;

import static org.junit.Assert.*;

import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.*;

import org.junit.Assert;
import org.junit.Test;

import docking.widgets.label.GDHtmlLabel;
import generic.test.AbstractGenericTest;
import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.util.exception.DuplicateNameException;

public class HTMLDataTypeRepresentationTest extends AbstractGenericTest {

	public HTMLDataTypeRepresentationTest() {
		super();
	}

	@Test
	public void testCompositeWithFieldNameDifference() {
		Composite composite = get_DLL_Table_Instance();
		DataType dataTypeCopy = composite.copy(null);
		Composite compositeCopy = (Composite) dataTypeCopy;
		int fieldIndex = 0;
		setName(compositeCopy, fieldIndex);

		HTMLDataTypeRepresentation representation = ToolTipUtils.getHTMLRepresentation(composite);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(dataTypeCopy);

		assertTrue(representation instanceof CompositeDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation.diff(otherRepresentation);
//showDiffs( diffedRepresentations[0], diffedRepresentations[1] );

		showDiffs(diff[0], diff[1]);

		assertOnlyNameFieldDifferent(fieldIndex, diff);
		assertCompositeHeaderEquals(diff);
	}

	@Test
	public void testCompositeWithFieldCommentDifference() {
		Composite composite = get_DLL_Table_Instance();
		DataType dataTypeCopy = composite.copy(null);
		int fieldIndex = 3;
		DataTypeComponent component = composite.getComponent(fieldIndex);
		component.setComment("comment one");

		HTMLDataTypeRepresentation representation = ToolTipUtils.getHTMLRepresentation(composite);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(dataTypeCopy);

		assertTrue(representation instanceof CompositeDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation.diff(otherRepresentation);
		showDiffs(diff[0], diff[1]);

//showDiffs( diffedRepresentations[0], diffedRepresentations[1] );

		assertOnlyCommentFieldDifferent(fieldIndex, diff);
		assertCompositeHeaderEquals(diff);
	}

	@Test
	public void testCompositeWithHeaderCommentDifference() {
		Composite composite = get_DLL_Table_Instance();
		DataType dataTypeCopy = composite.copy(null);
		Composite compositeCopy = (Composite) dataTypeCopy;

		String commentString1 =
			"This is the first comment with a the different value.  This is some text to split the line.";
		String commentString2 =
			"This is the other comment with a the different value.  This is some text to split the line.";

		composite.setDescription(commentString1);
		compositeCopy.setDescription(commentString2);

		HTMLDataTypeRepresentation representation = ToolTipUtils.getHTMLRepresentation(composite);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(dataTypeCopy);

		assertTrue(representation instanceof CompositeDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation.diff(otherRepresentation);
		showDiffs(diff[0], diff[1]);

		assertBodyContentMatches(diff);

		int commentDifferenceLine = 1;
		assertCompositeHeaderDiffers_AtIndex(diff, commentDifferenceLine);
	}

	@Test
	public void testCompositeWithHeaderLengthDifferences_ForSCR_6813() {
		Composite composite = get_DLL_Table_Instance();

		DataType dataTypeCopy = composite.copy(null);

		String commentString1 =
			"This is the first comment with a the different value.  This is some text to split the line.";

		composite.setDescription(commentString1);

		HTMLDataTypeRepresentation representation = ToolTipUtils.getHTMLRepresentation(composite);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(dataTypeCopy);

		assertTrue(representation instanceof CompositeDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diffs = representation.diff(otherRepresentation);
		showDiffs(diffs[0], diffs[1]);

		assertBodyContentMatches(diffs);
		assertCompositeHeaderDiffers(diffs);
	}

	@Test
	public void testDefaultRepresentation_NotDifferent() {
		StringDataType stringy = new StringDataType();
		StringDataType stringy2 = new StringDataType();

		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(stringy);
		HTMLDataTypeRepresentation representation2 = ToolTipUtils.getHTMLRepresentation(stringy2);

		assertTrue(representation1 instanceof DefaultDataTypeHTMLRepresentation);
		assertTrue(representation2 instanceof DefaultDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation1.diff(representation2);
		showDiffs(diff[0], diff[1]);

//showDiffs( diffedRepresentations[0], diffedRepresentations[1] );
		TextLine header1 = ((DefaultDataTypeHTMLRepresentation) diff[0]).header;
		TextLine footer1 = ((DefaultDataTypeHTMLRepresentation) diff[0]).footer;

		TextLine header2 = ((DefaultDataTypeHTMLRepresentation) diff[1]).header;
		TextLine footer2 = ((DefaultDataTypeHTMLRepresentation) diff[1]).footer;

		assertTrue(header1.matches(header2));
		assertTrue(footer1.matches(footer2));

		assertEquals(header1.getTextColor(), header2.getTextColor());
		assertEquals(footer1.getTextColor(), footer2.getTextColor());
	}

	@Test
	public void testDefaultRepresentation_Different() {

		StringDataType stringy = new StringDataType();
		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(stringy);

		ByteDataType bytey = new ByteDataType();
		HTMLDataTypeRepresentation representation2 = ToolTipUtils.getHTMLRepresentation(bytey);
		assertTrue(representation2 instanceof DefaultDataTypeHTMLRepresentation);

		assertTrue(representation1 instanceof DefaultDataTypeHTMLRepresentation);
		HTMLDataTypeRepresentation[] diff = representation1.diff(representation2);
		showDiffs(diff[0], diff[1]);

		TextLine header1 = ((DefaultDataTypeHTMLRepresentation) diff[0]).header;
		TextLine footer1 = ((DefaultDataTypeHTMLRepresentation) diff[0]).footer;

		TextLine header2 = ((DefaultDataTypeHTMLRepresentation) diff[1]).header;
		TextLine footer2 = ((DefaultDataTypeHTMLRepresentation) diff[1]).footer;

		assertTrue(!header1.matches(header2));
		assertTrue(!footer1.matches(footer2));

		assertEquals(header1.getTextColor(), ValidatableLine.INVALID_COLOR);
		assertEquals(header1.getTextColor(), header2.getTextColor());
		assertEquals(footer1.getTextColor(), footer2.getTextColor());
	}

	@Test
	public void testEnumRepresentation() {
		//
		// The algorithms used by the enum representations are also used by the structure
		// representation, so we will not test the enum as thoroughly here
		//

		EnumDataType enumDataType = createEnumDataType();

		// use another enum with a value inserted
		EnumDataType otherEnumDataType = createEnumDataType();
		otherEnumDataType.add("NEW_VALUE", 0x4);

		HTMLDataTypeRepresentation representation =
			ToolTipUtils.getHTMLRepresentation(enumDataType);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(otherEnumDataType);

		assertTrue(representation instanceof EnumDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof EnumDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diffs = representation.diff(otherRepresentation);
		showDiffs(diffs[0], diffs[1]);

		// this is based upon the enum values and the value of our inserted entry
		int insertIndex = 2;
		assertEnumBodyDiffs_EmptyAtIndex(diffs, insertIndex);
	}

	@Test
	public void testFunction_DifferentName() {
		FunctionDefinitionDataType function1 = createFunctionDefinition();
		FunctionDefinitionDataType function2 = createFunctionDefinition();

		setName(function2, "newFunctionName");

		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(function1);
		HTMLDataTypeRepresentation representation2 = ToolTipUtils.getHTMLRepresentation(function2);

		assertTrue(representation1 instanceof FunctionDataTypeHTMLRepresentation);
		assertTrue(representation2 instanceof FunctionDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation1.diff(representation2);
		showDiffs(diff[0], diff[1]);

		assertReturnTypeMatches(functionRep(diff[0]), functionRep(diff[1]));
		assertNameDifferent(functionRep(diff[0]), functionRep(diff[1]));
		assertArgumentsMatches(functionRep(diff[0]), functionRep(diff[1]));
		assertVarArgsMatches(functionRep(diff[0]), functionRep(diff[1]));
	}

	@Test
	public void testFunction_DifferentParameterCount() {
		//
		// different number of parameters
		//
		FunctionDefinitionDataType function1 = createFunctionDefinition();
		FunctionDefinitionDataType function2 = createFunctionDefinitionWith3Parameters();

		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(function1);
		HTMLDataTypeRepresentation representation2 = ToolTipUtils.getHTMLRepresentation(function2);

		assertTrue(representation1 instanceof FunctionDataTypeHTMLRepresentation);
		assertTrue(representation2 instanceof FunctionDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diffs = representation1.diff(representation2);
		showDiffs(diffs[0], diffs[1]);

		assertReturnTypeMatches(functionRep(diffs[0]), functionRep(diffs[1]));
		assertNameMatches(functionRep(diffs[0]), functionRep(diffs[1]));

		int emptyIndex = 2;
		assertArgumentsDiff_EmptyAtIndex(emptyIndex, functionRep(diffs[0]), functionRep(diffs[1]));
		assertVarArgsMatches(functionRep(diffs[0]), functionRep(diffs[1]));
	}

	@Test
	public void testFunction_SameParameters_DifferentParameterName() {
		FunctionDefinitionDataType function1 = createFunctionDefinition();
		FunctionDefinitionDataType function2 = createFunctionDefinition();

		setParameterName(function2, 0, "newFirstParamName");

		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(function1);
		HTMLDataTypeRepresentation representation2 = ToolTipUtils.getHTMLRepresentation(function2);

		assertTrue(representation1 instanceof FunctionDataTypeHTMLRepresentation);
		assertTrue(representation2 instanceof FunctionDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation1.diff(representation2);
		showDiffs(diff[0], diff[1]);

		assertReturnTypeMatches(functionRep(diff[0]), functionRep(diff[1]));
		assertNameMatches(functionRep(diff[0]), functionRep(diff[1]));
		assertArgumentsDiffAtIndex_DifferentName(0, functionRep(diff[0]), functionRep(diff[1]));// first param
		assertArgumentsMatchAtIndex(1, functionRep(diff[0]), functionRep(diff[1]));// second param
		assertVarArgsMatches(functionRep(diff[0]), functionRep(diff[1]));
	}

	@Test
	public void testFunction_SameParameters_DifferentType() {
		FunctionDefinitionDataType function1 = createFunctionDefinition();
		FunctionDefinitionDataType function2 = createFunctionDefinition();

		setParameterType(function2, 0, new CharDataType());

		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(function1);
		HTMLDataTypeRepresentation representation2 = ToolTipUtils.getHTMLRepresentation(function2);

		assertTrue(representation1 instanceof FunctionDataTypeHTMLRepresentation);
		assertTrue(representation2 instanceof FunctionDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation1.diff(representation2);
		showDiffs(diff[0], diff[1]);

		assertReturnTypeMatches(functionRep(diff[0]), functionRep(diff[1]));

		assertArgumentsDiffAtIndex_DifferentDataType(0, functionRep(diff[0]), functionRep(diff[1]));// first param
		assertArgumentsMatchAtIndex(1, functionRep(diff[0]), functionRep(diff[1]));// second param
		assertVarArgsMatches(functionRep(diff[0]), functionRep(diff[1]));
	}

	@Test
	public void testFunction_DifferentReturnType() {
		FunctionDefinitionDataType function1 = createFunctionDefinition();
		FunctionDefinitionDataType function2 = createFunctionDefinition();

		setReturnType(function2, function2);

		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(function1);
		HTMLDataTypeRepresentation representation2 = ToolTipUtils.getHTMLRepresentation(function2);

		assertTrue(representation1 instanceof FunctionDataTypeHTMLRepresentation);
		assertTrue(representation2 instanceof FunctionDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation1.diff(representation2);
		showDiffs(diff[0], diff[1]);

		assertReturnTypeDiffers(functionRep(diff[0]), functionRep(diff[1]));
	}

	@Test
	public void testFunction_UnnamedArgument() {

		FunctionDefinitionDataType function = new FunctionDefinitionDataType("myFunction");
		String nullName = null;
		ParameterDefinition param1 = new ParameterDefinitionImpl(nullName, new ByteDataType(), "");
		ParameterDefinition[] variables = new ParameterDefinition[] { param1 };
		function.setArguments(variables);
		function.setReturnType(new VoidDataType());

		HTMLDataTypeRepresentation rep = ToolTipUtils.getHTMLRepresentation(function);
		String html = rep.getHTMLString();

		// check that there is no param name (this is a bit hacky, but will do)
		String paramText = getParamText(html);
		assertEquals("byte", paramText);
	}

	private String getParamText(String html) {

		// function html format: 
		// 	<HTML>void&nbsp;myFunction(<BR>&nbsp;&nbsp;&nbsp;&nbsp;byte&nbsp;)<BR></HTML>

		Pattern p = Pattern.compile("\\((.*)\\)");
		Matcher matcher = p.matcher(html);
		matcher.find();
		String paramText = matcher.group(1);
		paramText = paramText.replace("&nbsp;", "");
		paramText = paramText.replace("<BR>", "");
		return paramText;
	}

	// @Test
	public void testPointerRepresentation() {
		// these aren't diffable yet, so nothing really to test
	}

	@Test
	public void testCompositeWithDifferentNumberOfComponents_SingleInsertInLeftHandComposite() {
		//
		// Make sure one blank row is inserted
		//
		// --we can test this simply by inserting a new datatype into a structure
		//
		Composite composite = get_DLL_Table_Instance();
		Composite compositeCopy = createCompositeCopy(composite);
		int insertIndex = 2;
		insertCopyAtIndex(compositeCopy, insertIndex, null);

		HTMLDataTypeRepresentation representation = ToolTipUtils.getHTMLRepresentation(composite);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(compositeCopy);

		assertTrue(representation instanceof CompositeDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation.diff(otherRepresentation);
		showDiffs(diff[0], diff[1]);

		assertCompositeBodyDiffers_EmptyAtIndex(diff, insertIndex);
	}

	@Test
	public void testCompositeWithDifferentNumberOfComponents_SingleInsertAtNextIndex() {
		//
		// Make sure multiple blank rows *in a contiguous sequence* are preserved.
		//
		Composite composite = get_DLL_Table_Instance();
		Composite compositeCopy = createCompositeCopy(composite);
		int insertIndex = 2;
		insertCopyAtIndex(compositeCopy, insertIndex, null);

		int secondInsertIndex = insertIndex + 1;
		insertCopyAtIndex(compositeCopy, secondInsertIndex);

		HTMLDataTypeRepresentation representation = ToolTipUtils.getHTMLRepresentation(composite);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(compositeCopy);

		assertTrue(representation instanceof CompositeDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation.diff(otherRepresentation);
		showDiffs(diff[0], diff[1]);

		assertCompositeBodyDiffers_EmptyAtIndex(diff, insertIndex, secondInsertIndex);
	}

	@Test
	public void testCompositeWithDifferentNumberOfComponents_SingleInsertAtDifferentOffsets() {
		//
		// Test one blank row in each at different indices
		//

		Composite composite = get_DLL_Table_Instance();
		Composite compositeWithOneBlankRowA = createCompositeCopy(composite);
		Composite compositeWithOneBlankRowB = createCompositeCopy(composite);

		int insertIndexA = 2;
		int insertIndexB = 5;
		insertCopyAtIndex(compositeWithOneBlankRowA, insertIndexA);
		insertCopyAtIndex(compositeWithOneBlankRowB, insertIndexB);

		HTMLDataTypeRepresentation representation =
			ToolTipUtils.getHTMLRepresentation(compositeWithOneBlankRowA);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(compositeWithOneBlankRowB);

		assertTrue(representation instanceof CompositeDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation.diff(otherRepresentation);
		showDiffs(diff[0], diff[1]);

		List<ValidatableLine> fieldList =
			((CompositeDataTypeHTMLRepresentation) diff[0]).bodyContent;
		List<ValidatableLine> otherFieldList =
			((CompositeDataTypeHTMLRepresentation) diff[1]).bodyContent;

		// even though we've added a field, the original list should have an empty row added to
		// make it the same size
		assertEquals(fieldList.size(), otherFieldList.size());
		for (int i = 0; i < fieldList.size(); i++) {
			DataTypeLine dataTypeLine = (DataTypeLine) fieldList.get(i);
			DataTypeLine otherDataTypeLine = (DataTypeLine) otherFieldList.get(i);
			if (i == (insertIndexB + 1)) {// add one since the lines already had an empty line added
				// this one should be empty...
				assertTrue(dataTypeLine instanceof EmptyDataTypeLine);

				// ...and the other should be colored
				assertNotNull(otherDataTypeLine.getNameColor());
				assertNotNull(otherDataTypeLine.getTypeColor());
			}
			else if (i == insertIndexA) {
				// this one should be empty for the other line
				assertTrue(otherDataTypeLine instanceof EmptyDataTypeLine);

				// ...and the first one should be colored
				assertNotNull(dataTypeLine.getNameColor());
				assertNotNull(dataTypeLine.getTypeColor());
				assertNotNull(dataTypeLine.getCommentColor());
			}
			else {
				assertTrue(dataTypeLine.matches(otherDataTypeLine));
				assertNull(otherDataTypeLine.getNameColor());
				assertNull(otherDataTypeLine.getTypeColor());
				assertNull(otherDataTypeLine.getCommentColor());
			}
		}
	}

	@Test
	public void testCompositeWithDifferentNumberOfComponents_MultiSpanInsertAtDifferentOffsets() {
		//
		// Test multiple contiguous blank rows in each, at non-intersecting indices (these should
		// have empty rows for each inserted value).
		//

		Composite composite = get_DLL_Table_Instance();

		Composite compositeWithManyBlankRowsA = createCompositeCopy(composite);
		Composite compositeWithManyBlankRowsB = createCompositeCopy(composite);
		int multipleInsertIndex = 1;
		int secondMultipleInsertIndex = 5;
		insertCopyAtIndex(compositeWithManyBlankRowsA, multipleInsertIndex);
		insertCopyAtIndex(compositeWithManyBlankRowsA, multipleInsertIndex);
		insertCopyAtIndex(compositeWithManyBlankRowsA, multipleInsertIndex);

		insertCopyAtIndex(compositeWithManyBlankRowsB, secondMultipleInsertIndex);
		insertCopyAtIndex(compositeWithManyBlankRowsB, secondMultipleInsertIndex);
		insertCopyAtIndex(compositeWithManyBlankRowsB, secondMultipleInsertIndex);

		HTMLDataTypeRepresentation representation =
			ToolTipUtils.getHTMLRepresentation(compositeWithManyBlankRowsA);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(compositeWithManyBlankRowsB);

		assertTrue(representation instanceof CompositeDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation.diff(otherRepresentation);
		showDiffs(diff[0], diff[1]);

		List<ValidatableLine> fieldList =
			((CompositeDataTypeHTMLRepresentation) diff[0]).bodyContent;
		List<ValidatableLine> otherFieldList =
			((CompositeDataTypeHTMLRepresentation) diff[1]).bodyContent;

		// even though we've added a field, the original list should have an empty row added to
		// make it the same size
		assertEquals(fieldList.size(), otherFieldList.size());
	}

	@Test
	public void testCompositeWithDifferentNumberOfComponents_InsertAtOveralppingOffsets() {
		//
		// Test multiple contiguous blank rows in each, at overlapping indices (these should
		// condense such that we do not have an equal number of empty rows for the inserted
		// rows).
		//
		// Initially, adding multiple entries into each structure will trigger empty rows to be
		// placed into the opposite structure.  However, since the insertions overlap, the
		// diff algorithm will condense ranges of empty rows that are at the same index.  So,
		// below we add 4 members to one structure and 3 to the other.  After the diff has taken
		// place we should only have one empty row (4-3) in the structure that contained less
		// inserts initially.
		//

		Composite composite = get_DLL_Table_Instance();

		Composite compositeWithOverlappingManyBlankRowsA = createCompositeCopy(composite);
		Composite compositeWithOverlappingManyBlankRowsB = createCompositeCopy(composite);
		int multipleInsertIndex = 1;
		int secondMultipleInsertIndex = multipleInsertIndex + 1;
		insertCopyAtIndex(compositeWithOverlappingManyBlankRowsA, multipleInsertIndex);
		insertCopyAtIndex(compositeWithOverlappingManyBlankRowsA, multipleInsertIndex);
		insertCopyAtIndex(compositeWithOverlappingManyBlankRowsA, multipleInsertIndex);
		insertCopyAtIndex(compositeWithOverlappingManyBlankRowsA, multipleInsertIndex);

		insertCopyAtIndex(compositeWithOverlappingManyBlankRowsB, secondMultipleInsertIndex);
		insertCopyAtIndex(compositeWithOverlappingManyBlankRowsB, secondMultipleInsertIndex);
		insertCopyAtIndex(compositeWithOverlappingManyBlankRowsB, secondMultipleInsertIndex);

		HTMLDataTypeRepresentation representation =
			ToolTipUtils.getHTMLRepresentation(compositeWithOverlappingManyBlankRowsA);
		HTMLDataTypeRepresentation otherRepresentation =
			ToolTipUtils.getHTMLRepresentation(compositeWithOverlappingManyBlankRowsB);

		assertTrue(representation instanceof CompositeDataTypeHTMLRepresentation);
		assertTrue(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation);

		HTMLDataTypeRepresentation[] diff = representation.diff(otherRepresentation);
		showDiffs(diff[0], diff[1]);

		List<ValidatableLine> fieldList =
			((CompositeDataTypeHTMLRepresentation) diff[0]).bodyContent;
		List<ValidatableLine> otherFieldList =
			((CompositeDataTypeHTMLRepresentation) diff[1]).bodyContent;

		showDiffs(diff[0], diff[1]);

		// even though we've added a field, the original list should have an empty row added to
		// make it the same size
		assertEquals(fieldList.size(), otherFieldList.size());

		// only the structure with less inserts (structure B) should have 1 empty row
		int expectedEmptyIndex = secondMultipleInsertIndex + 3;// 3 inserts
		int length = fieldList.size();
		for (int i = 0; i < length; i++) {
			DataTypeLine dataTypeLine = (DataTypeLine) otherFieldList.get(i);
			if (i == expectedEmptyIndex) {
				assertTrue(dataTypeLine instanceof EmptyDataTypeLine);
			}
			else {
				assertTrue(!(dataTypeLine instanceof EmptyDataTypeLine));
			}
			DataTypeLine otherDataTypeLine = (DataTypeLine) fieldList.get(i);
			assertTrue(!(otherDataTypeLine instanceof EmptyDataTypeLine));
		}
	}

	@Test
	public void testCompositeCopyWithDataTypeEnlarged_SCR_10448() {

		Structure struct1 = getStructWithEnum();
		CompositeDataTypeHTMLRepresentation originalRep =
			new CompositeDataTypeHTMLRepresentation(struct1);

		Structure struct2 = (Structure) struct1.copy(struct1.getDataTypeManager());
		struct2 = changeFirstElementToWord(struct2);
		CompositeDataTypeHTMLRepresentation changedRep =
			new CompositeDataTypeHTMLRepresentation(struct2);

		//
		// Manually use the internal methods, as we know where problem is
		//
		HTMLDataTypeRepresentation[] diff = originalRep.diff(changedRep);
		showDiffs(diff[0], diff[1]);

		TypedefDataType td1 = new TypedefDataType("Struct1", struct1);
		TypedefDataType td2 = new TypedefDataType("Struct2", struct2);
		TypeDefDataTypeHTMLRepresentation r1 = new TypeDefDataTypeHTMLRepresentation(td1);
		TypeDefDataTypeHTMLRepresentation r2 = new TypeDefDataTypeHTMLRepresentation(td2);
		HTMLDataTypeRepresentation[] tdDiffs = r1.diff(r2);
		showDiffs(tdDiffs[0], tdDiffs[1]);

		/*
		 	The resulting diff should look like
		
		 	Original
		
		 	byte
		 	enum
		 	byte
		
		 	Modified
		
		 	word
		 	enum
		 	byte
		
		 */

		CompositeDataTypeHTMLRepresentation composite1 =
			(CompositeDataTypeHTMLRepresentation) diff[0];
		CompositeDataTypeHTMLRepresentation composite2 =
			(CompositeDataTypeHTMLRepresentation) diff[1];

		List<ValidatableLine> body1 = composite1.bodyContent;
		List<ValidatableLine> body2 = composite2.bodyContent;

		assertEquals(3, body1.size());
		assertEquals(3, body2.size());
	}

	@Test
	public void testTypeDefDiff_Arrays_TwoDifferentBaseTypes() {

		DataType t1 = new IntegerDataType();
		ArrayDataType a1 = new ArrayDataType(t1, 4, t1.getLength());

		DataType t2 = new LongDataType();
		ArrayDataType a2 = new ArrayDataType(t2, 4, t2.getLength());

		TypedefDataType td1 = new TypedefDataType("TypeDef", a1);
		TypedefDataType td2 = new TypedefDataType("TypeDef", a2);

		TypeDefDataTypeHTMLRepresentation r1 = new TypeDefDataTypeHTMLRepresentation(td1);
		TypeDefDataTypeHTMLRepresentation r2 = new TypeDefDataTypeHTMLRepresentation(td2);

		HTMLDataTypeRepresentation[] diff = r1.diff(r2);
		showDiffs(diff[0], diff[1]);

		assertTypeDefHeaderAndBodiesDifferent(diff);
	}

	@Test
	public void testTypeDefDiff_Arrays_SameType_DifferentSize() {

		DataType t1 = new IntegerDataType();
		ArrayDataType a1 = new ArrayDataType(t1, 4, t1.getLength());

		DataType t2 = new IntegerDataType();
		ArrayDataType a2 = new ArrayDataType(t2, 2, t2.getLength());

		TypedefDataType td1 = new TypedefDataType("TypeDef", a1);
		TypedefDataType td2 = new TypedefDataType("TypeDef", a2);

		TypeDefDataTypeHTMLRepresentation r1 = new TypeDefDataTypeHTMLRepresentation(td1);
		TypeDefDataTypeHTMLRepresentation r2 = new TypeDefDataTypeHTMLRepresentation(td2);

		HTMLDataTypeRepresentation[] diff = r1.diff(r2);
		showDiffs(diff[0], diff[1]);

		assertOnlyHeaderAndTypeDefBodySizeDifferent(diff);
	}

	@Test
	public void testTypeDefDiff_Arrays_SameArrays() {

		DataType t1 = new IntegerDataType();
		ArrayDataType a1 = new ArrayDataType(t1, 4, t1.getLength());

		DataType t2 = new IntegerDataType();
		ArrayDataType a2 = new ArrayDataType(t2, 4, t2.getLength());

		TypedefDataType td1 = new TypedefDataType("TypeDef", a1);
		TypedefDataType td2 = new TypedefDataType("TypeDef", a2);

		TypeDefDataTypeHTMLRepresentation r1 = new TypeDefDataTypeHTMLRepresentation(td1);
		TypeDefDataTypeHTMLRepresentation r2 = new TypeDefDataTypeHTMLRepresentation(td2);

		HTMLDataTypeRepresentation[] diff = r1.diff(r2);
		showDiffs(diff[0], diff[1]);

		assertTypeDefsSame(diff);
	}

	@Test
	public void testTypeDefDiff_Arrays_SameArrays_DifferentNames() {

		DataType t1 = new IntegerDataType();
		ArrayDataType a1 = new ArrayDataType(t1, 4, t1.getLength());

		ArrayDataType a2 = (ArrayDataType) a1.copy(null);

		TypedefDataType td1 = new TypedefDataType("TypeDef1", a1);
		TypedefDataType td2 = new TypedefDataType("TypeDef2", a2);

		TypeDefDataTypeHTMLRepresentation r1 = new TypeDefDataTypeHTMLRepresentation(td1);
		TypeDefDataTypeHTMLRepresentation r2 = new TypeDefDataTypeHTMLRepresentation(td2);

		HTMLDataTypeRepresentation[] diff = r1.diff(r2);
		showDiffs(diff[0], diff[1]);

		assertOnlyTypeDefNamesDifferent(diff);
	}

	@Test
	public void testTypeDefDiff_ArraysOfStructures_DifferentStructures() {

		Structure s1 = getStructWithEnum();
		Structure s2 = (Structure) s1.copy(s1.getDataTypeManager());
		s2 = changeFirstElementToWord(s2);

		ArrayDataType a1 = new ArrayDataType(s1, 2, s1.getLength());
		ArrayDataType a2 = new ArrayDataType(s2, 2, s2.getLength());

		TypedefDataType td1 = new TypedefDataType("TypeDef", a1);
		TypedefDataType td2 = new TypedefDataType("TypeDef", a2);

		TypeDefDataTypeHTMLRepresentation r1 = new TypeDefDataTypeHTMLRepresentation(td1);
		TypeDefDataTypeHTMLRepresentation r2 = new TypeDefDataTypeHTMLRepresentation(td2);

		HTMLDataTypeRepresentation[] diff = r1.diff(r2);
		showDiffs(diff[0], diff[1]);

		assertOnlyTypeDefBodiesDifferent(diff);
	}

	@Test
	public void testBreakLongLines() {
		List<String> l0 = HTMLDataTypeRepresentation.breakLongLineAtWordBoundaries("", 10);
		assertEquals(0, l0.size());

		List<String> l1 = HTMLDataTypeRepresentation.breakLongLineAtWordBoundaries("a", 10);
		assertEquals(1, l1.size());
		assertEquals("a", l1.get(0));

		List<String> l2 = HTMLDataTypeRepresentation.breakLongLineAtWordBoundaries("a b", 10);
		assertEquals(1, l2.size());
		assertEquals("a b", l2.get(0));

		List<String> l3 = HTMLDataTypeRepresentation.breakLongLineAtWordBoundaries("a b c", 10);
		assertEquals(1, l3.size());
		assertEquals("a b c", l3.get(0));

		List<String> l3a =
			HTMLDataTypeRepresentation.breakLongLineAtWordBoundaries("aaa bbb ccc ddd", 10);
		assertEquals(2, l3a.size());
		assertEquals("aaa bbb ", l3a.get(0));
		assertEquals("ccc ddd", l3a.get(1));

		//[a bbbbbbbb, bbbbbbbbbb, bbbbbbbbbb, bbbbbb c]
		List<String> l4 = HTMLDataTypeRepresentation.breakLongLineAtWordBoundaries(
			"a bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb c", 10);
		assertEquals(4, l4.size());
		assertEquals("a bbbbbbbb", l4.get(0));
		assertEquals("bbbbbbbbbb", l4.get(1));
		assertEquals("bbbbbb c", l4.get(3));

		// [a bbbbbbbb, bbbbbbbbbb, bbbbbbbbbb, bbbbbb , ccccccccc , dd]
		List<String> l5 = HTMLDataTypeRepresentation.breakLongLineAtWordBoundaries(
			"a bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ccccccccc dd", 10);
		assertEquals(6, l5.size());
		assertEquals("a bbbbbbbb", l5.get(0));
		assertEquals("bbbbbbbbbb", l5.get(1));
		assertEquals("bbbbbbbbbb", l5.get(2));
		assertEquals("bbbbbb ", l5.get(3));
		assertEquals("ccccccccc ", l5.get(4));
		assertEquals("dd", l5.get(5));
	}
//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertOnlyHeaderAndTypeDefBodySizeDifferent(HTMLDataTypeRepresentation[] diff) {
		TypeDefDataTypeHTMLRepresentation td1 = (TypeDefDataTypeHTMLRepresentation) diff[0];
		TypeDefDataTypeHTMLRepresentation td2 = (TypeDefDataTypeHTMLRepresentation) diff[1];

		List<ValidatableLine> h1 = td1.headerContent;
		List<ValidatableLine> h2 = td2.headerContent;
		Assert.assertNotEquals("TypeDef diff should have different headers", h1, h2);

		List<ValidatableLine> b1 = td1.bodyContent;
		List<ValidatableLine> b2 = td2.bodyContent;

		// crude, but effective
		String s1 = b1.toString();
		String s2 = b2.toString();

		String size1 = s1.replaceAll(".*Size: (\\d+).*", "$1");
		String size2 = s2.replaceAll(".*Size: (\\d+).*", "$1");

		Assert.assertNotEquals("TypeDef diff should have different Size values", size1, size2);
	}

	private void assertTypeDefsSame(HTMLDataTypeRepresentation[] diff) {
		TypeDefDataTypeHTMLRepresentation td1 = (TypeDefDataTypeHTMLRepresentation) diff[0];
		TypeDefDataTypeHTMLRepresentation td2 = (TypeDefDataTypeHTMLRepresentation) diff[1];

		List<ValidatableLine> h1 = td1.headerContent;
		List<ValidatableLine> h2 = td2.headerContent;
		assertEquals("TypeDef diff should have same headers", h1, h2);

		List<ValidatableLine> b1 = td1.bodyContent;
		List<ValidatableLine> b2 = td2.bodyContent;
		assertEquals("TypeDef diff should have the same bodies", b1, b2);
	}

	private void assertOnlyTypeDefNamesDifferent(HTMLDataTypeRepresentation[] diff) {

		TypeDefDataTypeHTMLRepresentation td1 = (TypeDefDataTypeHTMLRepresentation) diff[0];
		TypeDefDataTypeHTMLRepresentation td2 = (TypeDefDataTypeHTMLRepresentation) diff[1];

		List<ValidatableLine> h1 = td1.headerContent;
		List<ValidatableLine> h2 = td2.headerContent;
		Assert.assertNotEquals("TypeDef diff should have different headers", h1, h2);

		List<ValidatableLine> b1 = td1.bodyContent;
		List<ValidatableLine> b2 = td2.bodyContent;
		assertEquals("TypeDef diff should have the same bodies", b1, b2);
	}

	private void assertOnlyTypeDefBodiesDifferent(HTMLDataTypeRepresentation[] diff) {
		TypeDefDataTypeHTMLRepresentation td1 = (TypeDefDataTypeHTMLRepresentation) diff[0];
		TypeDefDataTypeHTMLRepresentation td2 = (TypeDefDataTypeHTMLRepresentation) diff[1];

		List<ValidatableLine> h1 = td1.headerContent;
		List<ValidatableLine> h2 = td2.headerContent;
		assertEquals("TypeDef diff should have same headers", h1, h2);

		List<ValidatableLine> b1 = td1.bodyContent;
		List<ValidatableLine> b2 = td2.bodyContent;
		Assert.assertNotEquals("TypeDef diff should have different bodies", b1, b2);
	}

	private void assertTypeDefHeaderAndBodiesDifferent(HTMLDataTypeRepresentation[] diff) {
		TypeDefDataTypeHTMLRepresentation td1 = (TypeDefDataTypeHTMLRepresentation) diff[0];
		TypeDefDataTypeHTMLRepresentation td2 = (TypeDefDataTypeHTMLRepresentation) diff[1];

		List<ValidatableLine> h1 = td1.headerContent;
		List<ValidatableLine> h2 = td2.headerContent;
		Assert.assertNotEquals("TypeDef diff should have different headers", h1, h2);

		List<ValidatableLine> b1 = td1.bodyContent;
		List<ValidatableLine> b2 = td2.bodyContent;
		Assert.assertNotEquals("TypeDef diff should have different bodies", b1, b2);
	}

	private void assertCompositeHeaderDiffers_AtIndex(
			HTMLDataTypeRepresentation[] diffedRepresentations, int index) {

		List<ValidatableLine> headerLines =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[0]).headerContent;
		List<ValidatableLine> otherHeaderLines =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[1]).headerContent;
		assertEquals(headerLines.size(), otherHeaderLines.size());

		for (int i = 0; i < headerLines.size(); i++) {
			ValidatableLine textLine = headerLines.get(i);
			ValidatableLine otherTextLine = otherHeaderLines.get(i);
			if (i == index) {
				assertTrue(!textLine.matches(otherTextLine));
			}
			else {
				assertTrue(textLine.matches(otherTextLine));
			}
		}
	}

	private void assertEnumBodyDiffs_EmptyAtIndex(HTMLDataTypeRepresentation[] diffs, int index) {

		List<ValidatableLine> bodyLines = ((EnumDataTypeHTMLRepresentation) diffs[0]).bodyContent;
		List<ValidatableLine> otherBodyLines =
			((EnumDataTypeHTMLRepresentation) diffs[1]).bodyContent;
		assertEquals(bodyLines.size(), otherBodyLines.size());

		for (int i = 0; i < bodyLines.size(); i++) {
			TextLine textLine = (TextLine) bodyLines.get(i);
			TextLine otherTextLine = (TextLine) otherBodyLines.get(i);
			if (i == index) {
				assertTrue((textLine instanceof EmptyTextLine));
				assertTrue(!textLine.matches(otherTextLine));
				assertNotNull(otherTextLine.getTextColor());
			}
			else {
				assertTrue(textLine.matches(otherTextLine));
				assertNull(textLine.getTextColor());
				assertNull(otherTextLine.getTextColor());
			}
		}
	}

	private void setName(FunctionDefinitionDataType function, String name) {
		try {
			function.setName(name);
		}
		catch (Exception e) {
			e.printStackTrace();
			Assert.fail("Unexpected exception trying to rename a function");
		}
	}

	private void setParameterName(FunctionDefinitionDataType function, int ordinal, String name) {
		try {
			ParameterDefinition[] parameters = function.getArguments();
			parameters[ordinal].setName(name);
		}
		catch (Exception e) {
			e.printStackTrace();
			Assert.fail("Unexpected exception trying to set a function variable name");
		}
	}

	private void setParameterType(FunctionDefinitionDataType function, int ordinal, DataType dt) {
		try {
			ParameterDefinition[] parameters = function.getArguments();
			parameters[ordinal].setDataType(dt);
		}
		catch (Exception e) {
			e.printStackTrace();
			Assert.fail("Unexpected exception trying to set a function variable data type");
		}
	}

	private void assertOnlyCommentFieldDifferent(int fieldIndex,
			HTMLDataTypeRepresentation[] diffedRepresentations) {
		List<ValidatableLine> fieldList =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[0]).bodyContent;
		DataTypeLine dataTypeLine = (DataTypeLine) fieldList.get(fieldIndex);
		assertOnlyCommentDiffColored(dataTypeLine);

		List<ValidatableLine> otherFieldList =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[1]).bodyContent;
		DataTypeLine otherDataTypeLine = (DataTypeLine) otherFieldList.get(fieldIndex);
		assertOnlyCommentDiffColored(otherDataTypeLine);

		assertEquals(fieldList.size(), otherFieldList.size());
		for (int i = 1; i < fieldList.size(); i++) {
			if (i == fieldIndex) {
				continue;// skip the one we know is different
			}
			assertTrue("Field at " + i + " does not match",
				fieldList.get(i).matches(otherFieldList.get(i)));
		}
	}

	private void assertOnlyCommentDiffColored(DataTypeLine dataTypeLine) {
		assertTrue(dataTypeLine.getNameColor() == null);
		assertTrue(dataTypeLine.getTypeColor() == null);
		assertTrue(dataTypeLine.getCommentColor() != null);
	}

	private void assertBodyContentMatches(HTMLDataTypeRepresentation[] diffedRepresentations) {
		List<ValidatableLine> fieldList =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[0]).bodyContent;
		List<ValidatableLine> otherFieldList =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[1]).bodyContent;
		assertEquals(fieldList.size(), otherFieldList.size());

		for (int i = 1; i < fieldList.size(); i++) {
			assertTrue("Field at " + i + " does not match",
				fieldList.get(i).matches(otherFieldList.get(i)));
		}
	}

	private void assertCompositeHeaderDiffers(HTMLDataTypeRepresentation[] diffs) {
		List<ValidatableLine> headerLines =
			((CompositeDataTypeHTMLRepresentation) diffs[0]).headerContent;
		List<ValidatableLine> otherHeaderLines =
			((CompositeDataTypeHTMLRepresentation) diffs[1]).headerContent;

		assertTrue("Comments should be different!", !headerLines.equals(otherHeaderLines));
		assertTrue("Differing comments should have been padded to be the same nunber of lines",
			headerLines.size() == otherHeaderLines.size());
	}

	private EnumDataType createEnumDataType() {
		EnumDataType enumDataType = new EnumDataType("myEnum", 1);

		enumDataType.add("COMDLG32", 0x1);
		enumDataType.add("SHELL32", 0x3);
		enumDataType.add("MSVCRT", 0x5);
		enumDataType.add("ADVAPI32", 0x9);
		enumDataType.add("KERNEL32", 0x13);

		return enumDataType;
	}

	private FunctionDefinitionDataType createFunctionDefinition() {

		FunctionDefinitionDataType functionDataType = new FunctionDefinitionDataType("myFunction");

		ByteDataType bytey = new ByteDataType();
		ParameterDefinition param1 = new ParameterDefinitionImpl("byte_0", bytey, "");

		DWordDataType dword = new DWordDataType();
		ParameterDefinition param2 = new ParameterDefinitionImpl("dword_1", dword, "");

		ParameterDefinition[] variables = new ParameterDefinition[] { param1, param2 };
		functionDataType.setArguments(variables);

		functionDataType.setReturnType(new VoidDataType());

		return functionDataType;
	}

	private FunctionDefinitionDataType createFunctionDefinitionWith3Parameters() {
		FunctionDefinitionDataType functionDataType = new FunctionDefinitionDataType("myFunction");

		ByteDataType bytey = new ByteDataType();
		ParameterDefinition param1 = new ParameterDefinitionImpl("byte_0", bytey, "");

		DWordDataType dword = new DWordDataType();
		ParameterDefinition param2 = new ParameterDefinitionImpl("dword_1", dword, "");

		ParameterDefinition param3 = new ParameterDefinitionImpl("dword_2", dword, "");

		ParameterDefinition[] variables = new ParameterDefinition[] { param1, param2, param3 };
		functionDataType.setArguments(variables);

		functionDataType.setReturnType(new VoidDataType());

		return functionDataType;
	}

	private FunctionDataTypeHTMLRepresentation functionRep(HTMLDataTypeRepresentation rep) {
		return (FunctionDataTypeHTMLRepresentation) rep;
	}

	private void assertReturnTypeMatches(FunctionDataTypeHTMLRepresentation f1,
			FunctionDataTypeHTMLRepresentation f2) {
		TextLine returnLine = f1.returnType;
		TextLine otherReturnLine = f2.returnType;
		assertTrue(returnLine.matches(otherReturnLine));
		assertNull(returnLine.getTextColor());
		assertNull(otherReturnLine.getTextColor());
	}

	private void assertNameDifferent(FunctionDataTypeHTMLRepresentation f1,
			FunctionDataTypeHTMLRepresentation f2) {
		TextLine functionName = f1.functionName;
		TextLine otherFunctionName = f2.functionName;
		assertTrue(!functionName.matches(otherFunctionName));
		assertTrue(functionName.getTextColor().equals(ValidatableLine.INVALID_COLOR));
		assertTrue(functionName.getTextColor().equals(otherFunctionName.getTextColor()));
	}

	private void assertNameMatches(FunctionDataTypeHTMLRepresentation f1,
			FunctionDataTypeHTMLRepresentation f2) {
		TextLine functionName = f1.functionName;
		TextLine otherFunctionName = f2.functionName;
		assertTrue(functionName.matches(otherFunctionName));
		assertNull(functionName.getTextColor());
		assertNull(otherFunctionName.getTextColor());
	}

	private void assertArgumentsMatches(FunctionDataTypeHTMLRepresentation f1,
			FunctionDataTypeHTMLRepresentation f2) {
		List<ValidatableLine> arguments = f1.arguments;
		List<ValidatableLine> otherArguments = f2.arguments;
		assertEquals(arguments.size(), otherArguments.size());
		for (int i = 0; i < arguments.size(); i++) {
			VariableTextLine textLine = (VariableTextLine) arguments.get(i);
			VariableTextLine otherTextLine = (VariableTextLine) otherArguments.get(i);
			assertTrue(textLine.matches(otherTextLine));
			assertNull(textLine.getVariableTypeColor());
			assertNull(otherTextLine.getVariableNameColor());
		}
	}

	private void assertArgumentsDiffAtIndex_DifferentName(int index,
			FunctionDataTypeHTMLRepresentation f1, FunctionDataTypeHTMLRepresentation f2) {

		List<ValidatableLine> arguments = f1.arguments;
		List<ValidatableLine> otherArguments = f2.arguments;
		assertEquals(arguments.size(), otherArguments.size());

		VariableTextLine variableLine = (VariableTextLine) arguments.get(index);
		VariableTextLine otherVariableLine = (VariableTextLine) otherArguments.get(index);
		assertTrue(!variableLine.matches(otherVariableLine));
		assertNull(variableLine.getVariableTypeColor());
		assertNull(otherVariableLine.getVariableTypeColor());
		assertNotNull(variableLine.getVariableNameColor());
		assertNotNull(otherVariableLine.getVariableNameColor());
		assertEquals(variableLine.getVariableNameColor(), otherVariableLine.getVariableNameColor());
	}

	private void assertArgumentsDiffAtIndex_DifferentDataType(int index,
			FunctionDataTypeHTMLRepresentation f1, FunctionDataTypeHTMLRepresentation f2) {

		List<ValidatableLine> arguments = f1.arguments;
		List<ValidatableLine> otherArguments = f2.arguments;
		assertEquals(arguments.size(), otherArguments.size());

		VariableTextLine variableLine = (VariableTextLine) arguments.get(index);
		VariableTextLine otherVariableLine = (VariableTextLine) otherArguments.get(index);
		assertTrue(!variableLine.matches(otherVariableLine));
		assertNotNull(variableLine.getVariableTypeColor());
		assertNotNull(otherVariableLine.getVariableTypeColor());
		assertNull(variableLine.getVariableNameColor());
		assertNull(otherVariableLine.getVariableNameColor());
		assertEquals(variableLine.getVariableTypeColor(), otherVariableLine.getVariableTypeColor());
	}

	private void assertArgumentsMatchAtIndex(int index, FunctionDataTypeHTMLRepresentation f1,
			FunctionDataTypeHTMLRepresentation f2) {

		List<ValidatableLine> arguments = f1.arguments;
		List<ValidatableLine> otherArguments = f2.arguments;
		assertEquals(arguments.size(), otherArguments.size());

		VariableTextLine variableLine = (VariableTextLine) arguments.get(index);
		VariableTextLine otherVariableLine = (VariableTextLine) otherArguments.get(index);
		assertTrue(variableLine.matches(otherVariableLine));
		assertNull(variableLine.getVariableTypeColor());
		assertNull(otherVariableLine.getVariableTypeColor());
		assertNull(variableLine.getVariableNameColor());
		assertNull(otherVariableLine.getVariableNameColor());
	}

	private void assertArgumentsDiff_EmptyAtIndex(int index, FunctionDataTypeHTMLRepresentation f1,
			FunctionDataTypeHTMLRepresentation f2) {
		List<ValidatableLine> arguments = f1.arguments;
		List<ValidatableLine> otherArguments = f2.arguments;
		assertEquals(arguments.size(), otherArguments.size());

		for (int i = 0; i < arguments.size(); i++) {
			VariableTextLine textLine = (VariableTextLine) arguments.get(i);
			VariableTextLine otherTextLine = (VariableTextLine) otherArguments.get(i);
			if (i == index) {
				assertTrue(textLine instanceof EmptyVariableTextLine);
				assertTrue(
					otherTextLine.getVariableTypeColor().equals(ValidatableLine.INVALID_COLOR));
				assertTrue(
					otherTextLine.getVariableNameColor().equals(ValidatableLine.INVALID_COLOR));
			}
			else {
				assertTrue(textLine.matches(otherTextLine));
				assertNull(textLine.getVariableTypeColor());
				assertNull(textLine.getVariableNameColor());
			}
		}
	}

	private void assertVarArgsMatches(FunctionDataTypeHTMLRepresentation f1,
			FunctionDataTypeHTMLRepresentation f2) {

		TextLine varArgs = f1.varArgs;
		TextLine otherVarArgs = f2.varArgs;
		assertTrue(varArgs.matches(otherVarArgs));
		assertNull(varArgs.getTextColor());
		assertNull(otherVarArgs.getTextColor());
	}

	private void assertOnlyNameFieldDifferent(int fieldIndex,
			HTMLDataTypeRepresentation[] diffedRepresentations) {
		List<ValidatableLine> fieldList =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[0]).bodyContent;
		DataTypeLine dataTypeLine = (DataTypeLine) fieldList.get(fieldIndex);
		assertOnlyNameDiffColored(dataTypeLine);

		List<ValidatableLine> otherFieldList =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[1]).bodyContent;
		DataTypeLine otherDataTypeLine = (DataTypeLine) otherFieldList.get(fieldIndex);
		assertOnlyNameDiffColored(otherDataTypeLine);

		assertEquals(fieldList.size(), otherFieldList.size());
		for (int i = 0; i < fieldList.size(); i++) {
			if (i == fieldIndex) {
				continue;// skip the one we know is different
			}
			assertTrue("Field at " + i + " does not match",
				fieldList.get(i).matches(otherFieldList.get(i)));
		}
	}

	private void setName(Composite c, int fieldIndex) {
		DataTypeComponent component = c.getComponent(fieldIndex);
		try {
			component.setFieldName("newName");
		}
		catch (DuplicateNameException e) {
			// shouldn't happen
			e.printStackTrace();
			Assert.fail("Unexpected duplicate name");
		}
	}

	private void assertCompositeHeaderEquals(HTMLDataTypeRepresentation[] diffedRepresentations) {
		List<ValidatableLine> headerLines =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[0]).headerContent;
		List<ValidatableLine> otherHeaderLines =
			((CompositeDataTypeHTMLRepresentation) diffedRepresentations[1]).headerContent;
		assertEquals(headerLines, otherHeaderLines);
	}

	private void assertOnlyNameDiffColored(DataTypeLine dataTypeLine) {
		assertTrue(dataTypeLine.getNameColor() != null);
		assertTrue(dataTypeLine.getTypeColor() == null);
		assertTrue(dataTypeLine.getCommentColor() == null);
	}

	private void setReturnType(FunctionDefinitionDataType function, DataType dt) {
		try {
			function.setReturnType(dt);
		}
		catch (Exception e) {
			e.printStackTrace();
			Assert.fail("Unexpected exception trying to rename a function");
		}
	}

	private void assertReturnTypeDiffers(FunctionDataTypeHTMLRepresentation f1,
			FunctionDataTypeHTMLRepresentation f2) {
		TextLine returnLine = f1.returnType;
		TextLine otherReturnLine = f2.returnType;
		assertTrue(!returnLine.matches(otherReturnLine));
		assertEquals(returnLine.getTextColor(), otherReturnLine.getTextColor());
	}

	private void assertCompositeBodyDiffers_EmptyAtIndex(HTMLDataTypeRepresentation[] diffs,
			Integer... indices) {

		List<ValidatableLine> fieldList =
			((CompositeDataTypeHTMLRepresentation) diffs[0]).bodyContent;
		List<ValidatableLine> otherFieldList =
			((CompositeDataTypeHTMLRepresentation) diffs[1]).bodyContent;

		List<Integer> indexList = Arrays.asList(indices);

		// even though we've added a field, the original list should have an empty row added to
		// make it the same size
		assertEquals(fieldList.size(), otherFieldList.size());
		for (int i = 0; i < fieldList.size(); i++) {
			DataTypeLine dataTypeLine = (DataTypeLine) fieldList.get(i);
			DataTypeLine otherDataTypeLine = (DataTypeLine) otherFieldList.get(i);
			if (indexList.contains(i)) {
				// this one should be empty...
				assertTrue(dataTypeLine instanceof EmptyDataTypeLine);

				// ...and the other should be colored
				assertNotNull(otherDataTypeLine.getNameColor());
				assertNotNull(otherDataTypeLine.getTypeColor());
			}
			else {
				assertTrue(dataTypeLine.matches(otherDataTypeLine));
				assertNull(otherDataTypeLine.getNameColor());
				assertNull(otherDataTypeLine.getTypeColor());
				assertNull(otherDataTypeLine.getCommentColor());
			}
		}
	}

	private Structure getStructWithEnum() {
		// This is a structure that looks like:
		//
		// struct struct_Y {
		//		byte
		//      enumX
		//      byte
		// }
		//
		//
		// And enumX looks like:
		//
		// enumX {
		//		name1 = 0x0
		//      name2 = 0x1
		//      name3 = 0x2
		// }
		//

		EnumDataType enumm = new EnumDataType("enumX", 2);
		enumm.add("name1", 0x0);
		enumm.add("name2", 0x1);
		enumm.add("name3", 0x2);

		StructureDataType struct = new StructureDataType("struct_Y", 0);
		struct.add(new ByteDataType());
		struct.add(enumm);
		struct.add(new ByteDataType());

		return struct;
	}

	private Structure changeFirstElementToWord(Structure struct) {

		struct.delete(0);
		struct.insert(0, new WordDataType());

		return struct;
	}

	/**
	 *
	 *  The DLL_Table looks like this:
	 *<pre>
	 *DLL_Table {
	 *      string COMDLG32
	 *      string SHELL32
	 *      string MSVCRT
	 *      string ADVAPI32
	 *      string KERNEL32
	 *      string GDI32
	 *      string USER32
	 *      string WINSPOOL
	 *}
	 *</pre>
	 *
	 *
	 *
	 */
	private Composite get_DLL_Table_Instance() {

		StructureDataType structure = new StructureDataType("DLL_Table", 0);
		CategoryPath path = new CategoryPath("/");
		try {
			structure.setCategoryPath(path);

			StringDataType string = new StringDataType();
			structure.add(string, 1, "COMDLG32", "");

			string = new StringDataType();
			structure.add(string, 1, "SHELL32", "");

			string = new StringDataType();
			structure.add(string, 1, "MSVCRT", "");

			string = new StringDataType();
			structure.add(string, 1, "ADVAPI32", "");

			string = new StringDataType();
			structure.add(string, 1, "KERNEL32", "");

			string = new StringDataType();
			structure.add(string, 1, "GDI32", "");

			string = new StringDataType();
			structure.add(string, 1, "USER32", "");

			string = new StringDataType();
			structure.add(string, 1, "WINSPOOL", "");
		}
		catch (Exception e) {
			// shouldn't happen
			e.printStackTrace();
			Assert.fail("Somehow we have an unexpected exception in our environment.");
		}

		return structure;
	}

	private Composite createCompositeCopy(Composite composite) {
		Composite compositeCopy = (Composite) composite.copy(null);

		// the DLL_Table looks like this:
		// DLL_Table {
		//      string COMDLG32
		//      string SHELL32
		//      string MSVCRT
		//      string ADVAPI32
		//      string KERNEL32
		//      string GDI32
		//      string USER32
		//      string WINSPOOL
		// }
		//

		return compositeCopy;
	}

	private void insertCopyAtIndex(Composite composite, int insertIndex) {
		insertCopyAtIndex(composite, composite, insertIndex, null);
	}

	private void insertCopyAtIndex(Composite composite, int insertIndex, String optionalName) {
		insertCopyAtIndex(composite, composite, insertIndex, optionalName);
	}

	private void insertCopyAtIndex(Composite sourceComposite, Composite destinationComposite,
			int insertIndex, String optionalName) {
		DataTypeComponent componentAtIndex = sourceComposite.getComponent(insertIndex);
		DataType dataTypeAtIndex = componentAtIndex.getDataType();
		DataType componentCopy = dataTypeAtIndex.copy(null);
		String name = componentAtIndex.getFieldName();

		if (optionalName != null) {
			destinationComposite.insert(insertIndex, componentCopy, componentAtIndex.getLength(),
				optionalName, null);
		}
		else {
			destinationComposite.insert(insertIndex, componentCopy, componentAtIndex.getLength(),
				name + " Copy", null);
		}
	}

	@SuppressWarnings("unused")
	private void showDiffs(HTMLDataTypeRepresentation left, HTMLDataTypeRepresentation right) {

		// debug
		if (true) {
			return;
		}

		JFrame frame = new JFrame("HTML Highlighter Tester");

		JComponent content = buildSplitPane(left, right);

		frame.getContentPane().add(content);
		int width = 600;
		int height = 500;
		frame.setSize(width, height);
		Toolkit defaultToolkit = Toolkit.getDefaultToolkit();
		Dimension screenSize = defaultToolkit.getScreenSize();
		int x = (screenSize.width >> 1) - (width >> 1);
		int y = (screenSize.height >> 1) - (height >> 1);
		frame.setLocation(x, y);
		frame.setVisible(true);

		System.out.println("break point here");
	}

	private static JComponent buildSplitPane(HTMLDataTypeRepresentation left,
			HTMLDataTypeRepresentation right) {
		JPanel panel = new JPanel(new BorderLayout());

		JPanel rightPanel = new JPanel(new BorderLayout());
		String rightHtml = right.getHTMLString();
		System.err.println("Right HTML: " + rightHtml);
		StringBuffer buffy1 = new StringBuffer(rightHtml);
		JLabel rightLabel = new GDHtmlLabel();
		rightLabel.setOpaque(true);
		rightLabel.setBackground(Color.WHITE);
		rightLabel.setVerticalAlignment(SwingConstants.TOP);
		rightPanel.add(rightLabel);

		JPanel leftPanel = new JPanel(new BorderLayout());
		String leftHtml = left.getHTMLString();
		System.err.println("Left HTML: " + leftHtml);
		StringBuffer buffy2 = new StringBuffer(leftHtml);
		JLabel leftLabel = new GDHtmlLabel();
		leftLabel.setOpaque(true);
		leftLabel.setBackground(Color.WHITE);
		leftLabel.setVerticalAlignment(SwingConstants.TOP);
		leftPanel.add(leftLabel);

		rightLabel.setText(buffy1.toString());
		leftLabel.setText(buffy2.toString());

		JSplitPane pane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(leftPanel),
			new JScrollPane(rightPanel));
		pane.setResizeWeight(.5);
		panel.add(pane);

		return panel;
	}
}
