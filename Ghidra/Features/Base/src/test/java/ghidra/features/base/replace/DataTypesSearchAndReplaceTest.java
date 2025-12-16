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
package ghidra.features.base.replace;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

public class DataTypesSearchAndReplaceTest extends AbstractSearchAndReplaceTest {
	@Test
	public void testSearchDataTypes() throws Exception {
		addDataType(new StructureDataType("fooStruct", 1));
		addDataType(new UnionDataType("fooUnion"));
		addDataType(new EnumDataType("fooEnum", 4));
		addDataType(new TypedefDataType("fooTypeDef", new ByteDataType()));

		setSearchTypes(dataTypes);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(4, results.size());
		sortByName(results);

		assertQuickFix("fooEnum", "barEnum", results.get(0));
		assertQuickFix("fooStruct", "barStruct", results.get(1));
		assertQuickFix("fooTypeDef", "barTypeDef", results.get(2));
		assertQuickFix("fooUnion", "barUnion", results.get(3));
	}

	@Test
	public void testRenamingDataType() throws Exception {
		DataType dt = addDataType(new StructureDataType("fooStruct", 1));

		setSearchTypes(dataTypes);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Datatype", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("fooStruct", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("barStruct", item.getCurrent());
		assertEquals("barStruct", dt.getName());
	}

	@Test
	public void testRenamingDataTypeDuplicate() throws Exception {
		DataType dt = addDataType(new StructureDataType("fooStruct", 1));
		addDataType(new StructureDataType("barStruct", 1));

		setSearchTypes(dataTypes);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("Datatype with name \"barStruct\" already exists in category \"/\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Datatype", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("fooStruct", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.ERROR, item.getStatus());
		assertEquals(
			"Rename datatype failed: DataType named barStruct already exists in category /",
			item.getStatusMessage());
		assertEquals("fooStruct", item.getCurrent());
		assertEquals("fooStruct", dt.getName());
	}

	@Test
	public void testDataTypeDescriptionsStruct() throws Exception {
		StructureDataType struct = new StructureDataType("fooStruct", 1);
		struct.setDescription("this is a foo description");

		DataType structDB = addDataType(struct);

		setSearchTypes(dataTypeComments);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Datatype Description", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("this is a foo description", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("this is a bar description", item.getCurrent());
		assertEquals("this is a bar description", structDB.getDescription());
	}

	@Test
	public void testDataTypeDescriptionsEnum() throws Exception {
		EnumDataType enum1 = new EnumDataType("enum1", 4);
		enum1.add("aaa", 1);
		enum1.add("bbb", 2);
		enum1.setDescription("this is a foo description");

		DataType enumDB = addDataType(enum1);

		setSearchTypes(dataTypeComments);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Datatype Description", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("this is a foo description", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("this is a bar description", item.getCurrent());
		assertEquals("this is a bar description", enumDB.getDescription());
	}

	@Test
	public void testSearchFieldNames() throws Exception {
		StructureDataType dt1 = new StructureDataType("abc", 0);
		dt1.add(new ByteDataType(), "fooStructField", null);
		dt1.add(new ByteDataType(), "xxfooxxStructField", null);

		UnionDataType dt2 = new UnionDataType("abc");
		dt2.add(new ByteDataType(), "fooUnionField", null);
		dt2.add(new ByteDataType(), "xxfooxxUnionField", null);

		addDataType(dt1);
		addDataType(dt2);

		setSearchTypes(fieldNames);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(4, results.size());
		sortByName(results);

		assertQuickFix("fooStructField", "barStructField", results.get(0));
		assertQuickFix("fooUnionField", "barUnionField", results.get(1));
		assertQuickFix("xxfooxxStructField", "xxbarxxStructField", results.get(2));
		assertQuickFix("xxfooxxUnionField", "xxbarxxUnionField", results.get(3));
	}

	@Test
	public void testRenameStructureFieldNames() throws Exception {
		StructureDataType struct = new StructureDataType("abc", 0);
		struct.add(new ByteDataType(), "fooStructField", null);

		Structure dt = (Structure) addDataType(struct);

		setSearchTypes(fieldNames);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Field Name", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("fooStructField", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("barStructField", item.getCurrent());
		assertEquals("barStructField", dt.getComponent(0).getFieldName());

	}

	@Test
	public void testRenameUnionFieldNames() throws Exception {
		UnionDataType union = new UnionDataType("abc");
		union.add(new ByteDataType(), "fooUnionField", null);

		Union dt = (Union) addDataType(union);

		setSearchTypes(fieldNames);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Field Name", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("fooUnionField", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("barUnionField", item.getCurrent());
		assertEquals("barUnionField", dt.getComponent(0).getFieldName());

	}

	@Test
	public void testSearchFieldComments() throws Exception {
		StructureDataType dt1 = new StructureDataType("abc", 0);
		dt1.add(new ByteDataType(), "field1", "foo struct field1 comment");
		dt1.add(new ByteDataType(), "field2", "foo struct field2 comment");

		UnionDataType dt2 = new UnionDataType("abc");
		dt2.add(new ByteDataType(), "field1", "foo union field1 comment");
		dt2.add(new ByteDataType(), "field2", "foo union field2 comment");

		addDataType(dt1);
		addDataType(dt2);

		setSearchTypes(dataTypeComments);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(4, results.size());
		sortByName(results);

		assertQuickFix("foo struct field1 comment", "bar struct field1 comment", results.get(0));
		assertQuickFix("foo struct field2 comment", "bar struct field2 comment", results.get(1));
		assertQuickFix("foo union field1 comment", "bar union field1 comment", results.get(2));
		assertQuickFix("foo union field2 comment", "bar union field2 comment", results.get(3));
	}

	@Test
	public void testUpdateStructureFieldComments() throws Exception {
		StructureDataType dt1 = new StructureDataType("abc", 0);
		dt1.add(new ByteDataType(), "field1", "foo struct field1 comment");

		Structure dt = (Structure) addDataType(dt1);

		setSearchTypes(dataTypeComments);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Field Comment", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("foo struct field1 comment", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar struct field1 comment", item.getCurrent());
		assertEquals("bar struct field1 comment", dt.getComponent(0).getComment());

	}

	@Test
	public void testUpdateUnionFieldComments() throws Exception {
		UnionDataType dt1 = new UnionDataType("abc");
		dt1.add(new ByteDataType(), "field1", "foo union field1 comment");

		Union dt = (Union) addDataType(dt1);

		setSearchTypes(dataTypeComments);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Field Comment", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("foo union field1 comment", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar union field1 comment", item.getCurrent());
		assertEquals("bar union field1 comment", dt.getComponent(0).getComment());

	}

	@Test
	public void testSearchEnumValueNames() throws Exception {
		EnumDataType enum1 = new EnumDataType("enum1", 4);
		enum1.add("foo", 1);
		enum1.add("xxxfoo", 2);

		EnumDataType enum2 = new EnumDataType("enum2", 4);
		enum1.add("fooEnum2", 1);
		enum1.add("xxxfooEnum2", 2);

		addDataType(enum1);
		addDataType(enum2);

		setSearchTypes(enumValues);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(4, results.size());
		sortByName(results);

		assertQuickFix("foo", "bar", results.get(0));
		assertQuickFix("fooEnum2", "barEnum2", results.get(1));
		assertQuickFix("xxxfoo", "xxxbar", results.get(2));
		assertQuickFix("xxxfooEnum2", "xxxbarEnum2", results.get(3));
	}

	@Test
	public void testRenameEnumValueName() throws Exception {
		EnumDataType enum1 = new EnumDataType("enum1", 4);
		enum1.add("foo", 1);
		enum1.add("xxx", 2);

		Enum dt = (Enum) addDataType(enum1);
		setSearchTypes(enumValues);

		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Enum Value", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
		assertEquals("bar", dt.getName(1));
	}

	@Test
	public void testRenameEnumValueNameDuplicate() throws Exception {
		EnumDataType enum1 = new EnumDataType("enum1", 4);
		enum1.add("foo", 1);
		enum1.add("bar", 2);

		Enum dt = (Enum) addDataType(enum1);
		setSearchTypes(enumValues);

		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("New name not allowed because it duplicates an existing value name",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Enum Value", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.ERROR, item.getStatus());
		assertEquals("Rename enum value failed: bar already exists in this enum",
			item.getStatusMessage());
		assertEquals("foo", item.getCurrent());
		assertEquals("foo", dt.getName(1));
	}

	@Test
	public void testSearchEnumValueComments() throws Exception {
		EnumDataType enum1 = new EnumDataType("enum1", 4);
		enum1.add("ONE", 1, "ONE foo comment");
		enum1.add("TWO", 2, "TWO foo comment");

		EnumDataType enum2 = new EnumDataType("enum2", 4);
		enum1.add("THREE", 3, "THREE foo comment");
		enum1.add("FOUR", 4, "FOUR foo comment");

		addDataType(enum1);
		addDataType(enum2);

		setSearchTypes(dataTypeComments);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(4, results.size());
		sortByName(results);

		assertQuickFix("FOUR foo comment", "FOUR bar comment", results.get(0));
		assertQuickFix("ONE foo comment", "ONE bar comment", results.get(1));
		assertQuickFix("THREE foo comment", "THREE bar comment", results.get(2));
		assertQuickFix("TWO foo comment", "TWO bar comment", results.get(3));
	}

	@Test
	public void testUpdateEnumValueComments() throws Exception {
		EnumDataType enum1 = new EnumDataType("enum1", 4);
		enum1.add("ONE", 1, "ONE foo comment");
		Enum dt = (Enum) addDataType(enum1);

		setSearchTypes(dataTypeComments);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Enum Comment", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("ONE foo comment", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("ONE bar comment", item.getCurrent());
		assertEquals("ONE bar comment", dt.getComment("ONE"));

	}

}
