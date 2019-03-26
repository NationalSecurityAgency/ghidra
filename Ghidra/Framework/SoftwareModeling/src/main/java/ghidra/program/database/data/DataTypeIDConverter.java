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
package ghidra.program.database.data;

import java.io.*;
import java.util.Iterator;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.data.*;
import ghidra.util.NumericUtilities;
import ghidra.util.UniversalID;
import ghidra.util.datastruct.LongLongHashtable;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NoValueException;

public class DataTypeIDConverter implements GhidraLaunchable {

	private LongLongHashtable idMap;
	private int convertedCount = 0;
	private int builtInsCount = 0;
	private int nullIDsCount = 0;
	private int nonDataTypeDBCount = 0;
	private int notInMapCount = 0;

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) {
		if (args.length != 3) {
			System.out.println("DataTypeIDConverter <Input DataTypeArchive filepath> <ID map filepath> <Output DataTypeArchive filepath>");
			System.exit(1);
		}
		Application.initializeApplication(layout, new ApplicationConfiguration());
		System.out.println(" ");

		String inputArchivePath = args[0];
		String idMapFilePath = args[1];
		String outputArchivePath = args[2];

		File inFile = new File(inputArchivePath);
		File idMapFile = new File(idMapFilePath);
		File outFile = new File(outputArchivePath);

		if (outFile.exists()) {
			System.out.println("Output DataTypeArchive file \"" + outFile.getAbsolutePath() +
				"\" cannot already exist.");
			System.exit(1);
		}

		DataTypeIDConverter dataTypeIDConverter = new DataTypeIDConverter();

		dataTypeIDConverter.swap(inFile, idMapFile, outFile);

		System.out.println("DataTypeIDConverter:");
		System.out.println("  converted = " + dataTypeIDConverter.convertedCount);
		System.out.println("  nonDataTypeDB = " + dataTypeIDConverter.nonDataTypeDBCount);
		System.out.println("  builtIn = " + dataTypeIDConverter.builtInsCount);
		System.out.println("  nullIDs = " + dataTypeIDConverter.nullIDsCount);
		System.out.println("  notInMap = " + dataTypeIDConverter.notInMapCount);
	}

	private void swap(File inFile, File idMapFile, File outFile) {

		try {
			loadMap(idMapFile);
		}
		catch (InvalidInputException e) {
			e.printStackTrace();
			return;
		}
		catch (IOException e) {
			e.printStackTrace();
			return;
		}

		FileDataTypeManager oldFileArchive = null;
		try {
			oldFileArchive = FileDataTypeManager.openFileArchive(inFile, false);

			UniversalID oldFileUID = oldFileArchive.getUniversalID();
			long newID = idMap.get(oldFileUID.getValue());
			UniversalID newFileID = new UniversalID(newID);
			transformDataTypes(oldFileArchive);

			oldFileArchive.saveAs(outFile, newFileID);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		catch (NoValueException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally {
			if (oldFileArchive != null) {
				oldFileArchive.close();
			}
		}
	}

	private void loadMap(File idMapFile) throws InvalidInputException, IOException {
		// Get the IDs and place in a map.
		// This expects the idMapFile to contains lines where each line has an old ID in hex 
		// followed by a space and then a new ID in Hex.
		idMap = new LongLongHashtable();
		FileReader reader = new FileReader(idMapFile);
		BufferedReader bufferedReader = null;
		try {
			bufferedReader = new BufferedReader(reader);
			String line;
			while ((line = bufferedReader.readLine()) != null) {
				// Parse the two hex Data Type Universal IDs from the line.
				String[] tokens = line.split(" ");
				if (tokens.length != 2) {
					throw new InvalidInputException("Invalid line: " + line);
				}
				String oldIDString = tokens[0];
				String newIDString = tokens[1];
				long oldID = NumericUtilities.parseHexLong(oldIDString);
				long newID = NumericUtilities.parseHexLong(newIDString);
				if (idMap.contains(oldID)) {
					System.out.println("Duplicate oldID ID encountered: " + oldIDString);
//					throw new InvalidInputException("Duplicate oldID ID encountered: " +
//						oldIDString);
				}
				idMap.put(oldID, newID);
//				System.out.println(oldID + " 0x" + Long.toHexString(oldID) + "   " + newID + " 0x" +
//					Long.toHexString(newID));
			}
		}
		catch (NumberFormatException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			if (bufferedReader != null) {
				bufferedReader.close();
			}
		}
	}

	private void transformDataTypes(FileDataTypeManager oldFileArchive) {
		boolean commit = false;
		int transactionID = oldFileArchive.startTransaction("Transforming Data Type Archive");
		try {
			Iterator<DataType> allDataTypes = oldFileArchive.getAllDataTypes();
			while (allDataTypes.hasNext()) {
				DataType nextDt = allDataTypes.next();
				if (!(nextDt instanceof DataTypeDB)) {
					if (nextDt instanceof BuiltInDataType) {
						// Don't change built-ins.
//						System.out.println("Skipping Built-In Data Type: " + nextDt.getPathName());
						builtInsCount++;
					}
					else {
						// Needs to be a DB data type to change it.
						System.out.println("Skipping " + nextDt.getPathName() + "   class=" +
							nextDt.getClass());
						nonDataTypeDBCount++;
					}
					continue;
				}
				DataTypeDB dataType = (DataTypeDB) nextDt;
				UniversalID oldID = dataType.getUniversalID();
				if (oldID == null) {
					// Pointers don't have an ID.
//					System.out.println("No Universal ID for " + dataType.getPathName());
					nullIDsCount++;
					continue;
				}
				try {
					System.out.println("Old id = " + Long.toHexString(oldID.getValue()));
					long id = idMap.get(oldID.getValue());
					UniversalID newID = new UniversalID(id);
					dataType.setUniversalID(newID);

					// Set the archive data type's change time to the current time.
					// This should result in UPDATE status for data type when program looks at it.
					dataType.setLastChangeTime(System.currentTimeMillis());

//					System.out.println("Updated " + dataType.getPathName() + oldID + "->" + newID);
					convertedCount++;
				}
				catch (NoValueException e) {
					// No changes since not in the map.
					notInMapCount++;
//					System.out.println("No ID of " + oldID + " found in map for " +
//						dataType.getPathName() + ".");
				}
			}
			commit = true;
		}
		finally {
			oldFileArchive.endTransaction(transactionID, commit);
		}
	}
}
