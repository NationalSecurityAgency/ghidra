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
package ghidra.program.model.data;

import java.io.*;
import java.util.Iterator;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.dtarchive.DataTypeArchiveFactory;
import ghidra.program.model.dtarchive.FileDataTypeArchive;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DataTypeArchiveIdDumper implements GhidraLaunchable {

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args)
			throws IOException, CancelledException, VersionException {
		if (args.length != 2) {
			System.out.println("Usage: DataTypeArchiveDumper <ArchiveFileName> <outputFileName");
			System.exit(0);
		}
		Application.initializeApplication(layout, new ApplicationConfiguration());

		File archiveFile = new File(args[0]);
		File outputFile = new File(args[1]);

		FileWriter writer = new FileWriter(outputFile);
		FileDataTypeArchive archive =
			DataTypeArchiveFactory.openReadOnly(archiveFile, this, TaskMonitor.DUMMY);
		UniversalID universalID2 = archive.getDataTypeManager().getUniversalID();
		writer.write("FILE_ID: " + Long.toHexString(universalID2.getValue()));
		writer.write("\n");
		Iterator<DataType> it = archive.getDataTypeManager().getAllDataTypes();
		while (it.hasNext()) {
			DataType dt = it.next();
			UniversalID universalID = dt.getUniversalID();
			if (universalID != null) {
				String pathName = dt.getPathName();
				writer.write(Long.toHexString(universalID.getValue()));
				writer.write(" ");
				writer.write(pathName);
				writer.write("\n");
			}
			else {
				System.out.println("No id for " + dt.getPathName());
			}
		}
		writer.close();
		archive.release(this);
	}
}
