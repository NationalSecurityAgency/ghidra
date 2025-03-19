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
//
// Compare 2 file data type archives (.gdt). Output where data types exist only in one archive.
// Also indicate where the same named data type has a different type. This doesn't indicate
// where the internal contents of the same named data types differ.
//
//@category Data Types

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.StandAloneDataTypeManager.ArchiveWarning;
import ghidra.util.UniversalID;

public class CompareGDTs extends GhidraScript {

	private File firstFile;
	private File secondFile;
	private File outputFile;
	private FileDataTypeManager firstArchive;
	private FileDataTypeManager secondArchive;
	private PrintWriter printWriter;
	boolean matchByName;
	boolean checkPointers;
	boolean checkArrays;

	@Override
	protected void run() throws Exception {
		firstFile = askFile("Select First GDT File", "Select 1st");
		secondFile = askFile("Select Second GDT File", "Select 2nd");
		outputFile = askFile("Select Output File", "Select output file");
		if (outputFile.exists()) {
			boolean overwrite = askYesNo("Overwrite existing output file?",
				"The specified output file already exists. \nDo you want to overwrite it?");
			if (!overwrite) {
				println("Output file " + outputFile.getAbsolutePath() +
					" already exists. User aborted...");
				return;
			}
		}

		firstArchive = openDataTypeArchive(firstFile, false);
		if (firstArchive.getWarning() != ArchiveWarning.NONE) {
			popup(
				"An architecture language error occured while opening archive (see log for details)\n" +
					firstFile.getPath());
			return;
		}

		secondArchive = openDataTypeArchive(secondFile, false);
		if (secondArchive.getWarning() != ArchiveWarning.NONE) {
			popup(
				"An architecture language error occured while opening archive (see log for details)\n" +
					secondFile.getPath());
			firstArchive.close();
			return;
		}

		matchByName = askYesNo("Match Data Types By Path Name?",
			"Do you want to match data types by their path names (rather than by Universal ID)?");
		checkPointers = askYesNo("Check Pointers?", "Do you want to check Pointers?");
		checkArrays = askYesNo("Check Arrays?", "Do you want to check Arrays?");

		printWriter = new PrintWriter(outputFile);
		try {
			compareDataTypes();
		}
		finally {
			printWriter.close();
			firstArchive.close();
			secondArchive.close();
		}
	}

	private void output(String message) {
		printWriter.println(message);
	}

	private void compareDataTypes() {

		output("\nComparing " + firstFile.getAbsolutePath() + "\n        & " +
			secondFile.getAbsolutePath() + ".");

		output("\nThe following data types are only in " + firstFile.getAbsolutePath() + ".");
		long onlyInFirst = outputEachDataTypeOnlyInFirst(firstArchive, secondArchive);
		output(onlyInFirst + " data types that were only in first archive.");

		output("\nThe following data types are only in " + secondFile.getAbsolutePath() + ".");
		long onlyInSecond = outputEachDataTypeOnlyInFirst(secondArchive, firstArchive);
		output(onlyInSecond + " data types that were only in second archive.");

		output("\nThe following are different kinds of data types.");
		long differentKinds = outputWhereTypesDiffer(firstArchive, secondArchive);
		output(differentKinds + " data types had different types.");

		output("\nThe following data types are defined differently.");
		long differentDefinitions = outputWhereDefinitionsDiffer(firstArchive, secondArchive);
		output(differentDefinitions + " data types had different definitions.");

		output("\nThe following data types are different sizes");
		long differentSizes = outputWhereSizesDiffer(firstArchive, secondArchive);
		output(differentSizes + " data types had different sizes.");

		output("\n");
	}

	private long outputEachDataTypeOnlyInFirst(FileDataTypeManager dtmArchive1,
			FileDataTypeManager dtmArchive2) {

		long missingCount = 0;
		Iterator<DataType> allDataTypes = dtmArchive1.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			DataType dataType = allDataTypes.next();
			if (outputIfMissingDataType(dataType, dtmArchive2)) {
				missingCount++;
			}
		}
		return missingCount;
	}

	private boolean outputIfMissingDataType(DataType dataType, FileDataTypeManager dtmArchive) {

		if (!checkPointers && dataType instanceof Pointer) {
			return false;
		}

		if (!checkArrays && dataType instanceof Array) {
			return false;
		}

		DataType matchingDataType = getMatchingDataType(dataType, dtmArchive);
		if (matchingDataType == null) {
			String pathName = dataType.getPathName();
			output(pathName);
			return true;
		}
		return false;
	}

	private DataType getMatchingDataType(DataType dataType, FileDataTypeManager dtmArchive) {

		if (!matchByName) {
			UniversalID universalID = dataType.getUniversalID();
			if (universalID != null) {
				return dtmArchive.findDataTypeForID(universalID);
			}
		}

		// find by exact path
		DataType fdt = dtmArchive.getDataType(dataType.getCategoryPath(), dataType.getName());
		if (fdt != null) {
			return fdt;
		}

		// find by name
		List<DataType> list = new ArrayList<DataType>();
		dtmArchive.findDataTypes(dataType.getName(), list );
		for (DataType dtc : list) {
			if (dataType.getCategoryPath().getPath().toLowerCase().equals(dtc.getCategoryPath().getPath().toLowerCase())) {
				return dtc;
			}
		}
		return null;
	}

	private long outputWhereTypesDiffer(FileDataTypeManager dtmArchive1,
			FileDataTypeManager dtmArchive2) {

		long differCount = 0;
		Iterator<DataType> allDataTypes = dtmArchive1.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			DataType dataType = allDataTypes.next();
			if (outputIfDifferentTypes(dataType, dtmArchive2)) {
				differCount++;
			}
		}
		return differCount;
	}

	private long outputWhereSizesDiffer(FileDataTypeManager dtmArchive1,
			FileDataTypeManager dtmArchive2) {

		long differCount = 0;
		Iterator<DataType> allDataTypes = dtmArchive1.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			DataType dataType = allDataTypes.next();
			if (outputIfDifferentSizes(dataType, dtmArchive2)) {
				differCount++;
			}
		}
		return differCount;
	}

	private boolean outputIfDifferentTypes(DataType dataType, FileDataTypeManager dtmArchive) {

		if (!checkPointers && dataType instanceof Pointer) {
			return false;
		}

		if (!checkArrays && dataType instanceof Array) {
			return false;
		}

		DataType matchingDataType = getMatchingDataType(dataType, dtmArchive);
		if (matchingDataType != null) {
			Class<?> dtClass = dataType.getClass();
			Class<?> sameNamedDtClass = matchingDataType.getClass();
			if (dtClass != sameNamedDtClass) {
				String message = dataType.getPathName() + "   (" + dtClass.getSimpleName() + ") " +
					"   vs   (" + sameNamedDtClass.getClass() + ")";
				output(message);
				return true;
			}
		}
		return false;
	}

	private long outputWhereDefinitionsDiffer(FileDataTypeManager dtmArchive1,
			FileDataTypeManager dtmArchive2) {

		long differCount = 0;
		Iterator<DataType> allDataTypes = dtmArchive1.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			DataType dataType = allDataTypes.next();
			if (outputIfDifferentDefinitions(dataType, dtmArchive2)) {
				differCount++;
			}
		}
		return differCount;
	}

	private boolean outputIfDifferentDefinitions(DataType dataType,
			FileDataTypeManager dtmArchive) {

		if (!checkPointers && dataType instanceof Pointer) {
			return false;
		}

		if (!checkArrays && dataType instanceof Array) {
			return false;
		}

		DataType matchingDataType = getMatchingDataType(dataType, dtmArchive);
		if (matchingDataType != null) {
			Class<?> dtClass = dataType.getClass();
			Class<?> sameNamedDtClass = matchingDataType.getClass();
			if (dtClass == sameNamedDtClass) {
				if (dataType instanceof Enum && (((Enum) dataType).getCount()==1)) {
					// don't check single entry enums.  Size will vary, and they are extracted defines
					return checkEnum((Enum) dataType, (Enum) matchingDataType);
				}
				if (!dataType.isEquivalent(matchingDataType)) {
					String message =
						dataType.getPathName() + "   (" + dtClass.getSimpleName() + ")";
					output(message);
					return true;
				}
			}
		}
		return false;
	}

	private boolean checkEnum(Enum e1, Enum e2) {
		if (e1.getCount() != e2.getCount()) {
			return true;
		}
		// Check that the name is the same
		if (! e1.getNames()[0].equals(e2.getNames()[0])) {
			return true;
		}
		// Check the value is the same
		if (e1.getValues()[0] != e2.getValues()[0]) {
			return true;
		}		
		
		return false;
	}

	private boolean outputIfDifferentSizes(DataType dataType, FileDataTypeManager dtmArchive) {

		if (!checkPointers && dataType instanceof Pointer) {
			return false;
		}

		if (!checkArrays && dataType instanceof Array) {
			return false;
		}

		DataType matchingDataType = getMatchingDataType(dataType, dtmArchive);
		if (matchingDataType != null) {
			Class<?> dtClass = dataType.getClass();
			Class<?> sameNamedDtClass = matchingDataType.getClass();
			if (dtClass == sameNamedDtClass) {
				if (dataType instanceof Enum && (((Enum) dataType).getCount()==1)) {
					// don't check single entry enums.  Size will vary, and they are extracted defines
					return checkEnum((Enum) dataType, (Enum) matchingDataType);
				}
				if (dataType.getLength() != matchingDataType.getLength()) {
					String message = dataType.getPathName() + "   (" + dtClass.getSimpleName() +
						") " + dataType.getLength() + " !=  " + matchingDataType.getLength();
					output(message);
					return true;
				}
			}
		}
		return false;
	}
}
