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
package ghidra.app.merge.datatypes;

import static org.junit.Assert.*;

import javax.swing.JLabel;

import org.junit.Test;

import generic.test.TestUtils;
import ghidra.framework.main.*;
import ghidra.program.database.OriginalProgramModifierListener;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * More data type merge tests.
 * 
 * 
 */
public class DataTypeMerge8Test extends AbstractDataTypeMergeTest {

	@Test
	public void testConflictFixUpForNonFittingStruct() throws Exception {

		final CategoryPath miscPath = new CategoryPath("/MISC");
		final CategoryPath rootPath = new CategoryPath("/");

		FrontEndTool frontEndTool = mtf.getTestEnvironment().showFrontEndTool();

		mtf.initialize("notepad2", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				Structure xyz = new StructureDataType("XYZ", 0);
				xyz.add(new WordDataType());
				// struct XYZ {
				//      word
				// } (size=2)

				Structure abc = new StructureDataType("ABC", 0);
				abc.add(new ByteDataType());
				abc.add(new ByteDataType());
				abc.add(new WordDataType());
				abc.add(xyz);
				abc.add(DataType.DEFAULT);
				abc.add(new ByteDataType());
				// struct ABC {
				//     byte
				//     byte
				//     word
				//     XYZ (size=2)
				//     default
				//     byte
				// } (size=8)

				try {
					Category miscCategory = dtm.getCategory(miscPath);
					miscCategory.addDataType(abc, null);

					abc = (Structure) dtm.getDataType(miscPath, "ABC");
					xyz = (Structure) dtm.getDataType(rootPath, "XYZ");

					assertNotNull(abc);
					assertNotNull(xyz);

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				Structure abc = (Structure) dtm.getDataType(miscPath, "ABC");
				Structure xyz = (Structure) dtm.getDataType(rootPath, "XYZ");

				int transactionID = program.startTransaction("change ABC");
				try {
					// Change first byte in ABC to a char.
					abc.replace(0, new CharDataType(), 1);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

				transactionID = program.startTransaction("remove XYZ");
				try {
					// Remove the XYZ data type.
					dtm.remove(xyz, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				Structure abc = (Structure) dtm.getDataType(miscPath, "ABC");
				Structure xyz = (Structure) dtm.getDataType(rootPath, "XYZ");

				int transactionID = program.startTransaction("change ABC");
				try {
					// Change second byte in ABC to a char.
					abc.replace(1, new CharDataType(), 1);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

				transactionID = program.startTransaction("expand XYZ");
				try {
					// Increase the size of XYZ data type so it won't fit in its component.
					xyz.add(new FloatDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		frontEndTool.clearStatusInfo();

		executeMerge();

		// choose MY for Foo conflict
		chooseOption(DataTypeMergeManager.OPTION_MY);
		// choose MY for Bar conflict
		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		FrontEndPlugin frontEndPlugin = getPlugin(frontEndTool, FrontEndPlugin.class);
		LogPanel logPanel = (LogPanel) TestUtils.getInstanceField("statusPanel", frontEndPlugin);
		JLabel label = (JLabel) TestUtils.getInstanceField("label", logPanel);
		String statusText = label.getText();
		String expectedText =
			"Structure Merge: Not enough undefined bytes to fit /XYZ in structure " +
				"/MISC/ABC at offset 0x4. It needs 3 more byte(s) to be able to fit.";
		assertTrue("Wrong status text: " + statusText, statusText.contains(expectedText));
	}
}
