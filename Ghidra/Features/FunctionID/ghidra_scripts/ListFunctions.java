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
// Lets user choose a specific FID database and output file, then, for every function,
// dumps the executable domain path and function name.
//@category FunctionID
import java.io.*;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.*;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;

public class ListFunctions extends GhidraScript {

	private void writeFunctions(FidDB fidDb, Writer outWriter) throws IOException {
		long hash = Long.MIN_VALUE;
		for (;;) {
			Long longObj = fidDb.findFullHashValueAtOrAfter(hash);
			if (longObj == null) {
				break;
			}
			hash = longObj.longValue() + 1;
			List<FunctionRecord> funcList = fidDb.findFunctionsByFullHash(longObj.longValue());
			for (FunctionRecord rec : funcList) {
				outWriter.write(rec.getDomainPath());
				outWriter.write(' ');
				outWriter.write(rec.getName());
				outWriter.write('\n');
			}
		}
	}

	@Override
	protected void run() throws Exception {
		FidFileManager fidFileManager = FidFileManager.getInstance();
		List<FidFile> userFid = fidFileManager.getFidFiles();
		if (userFid.isEmpty()) {
			return;
		}
		FidFile fidFile =
			askChoice("List Functions", "Choose FID database", userFid, userFid.get(0));

		try (FidDB fidDb = fidFile.getFidDB(true)) {
			File outFile = askFile("Output file", "Choose output file: ");
			if (outFile == null) {
				return;
			}
			try (FileWriter out = new FileWriter(outFile)) {
				writeFunctions(fidDb, out);
			}
		}
		catch (VersionException e) {
			// Version upgrades are not supported
			Msg.showError(this, null, "Failed to open FidDb",
				"Failed to open incompatible FidDb (may need to regenerate with this version of Ghidra): " +
					fidFile.getPath());
			return;
		}

	}

}
