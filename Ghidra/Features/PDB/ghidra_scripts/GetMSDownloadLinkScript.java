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
//Creates a http download URL for a binary that Microsoft has previously published on their symbol server
// (ie. windows OS binaries).  Useful for sharing an exact Windows OS binary from your local 
// workstation to someone else without requiring the recipient to trust your binary as they
// can download it directly from Microsoft's symbol server.
// This works by extracting 2 pieces of metadata from the chosen binary's PE header to create
// the URL to Microsoft's symbol server and verifying that it exists on Microsoft's symbol server
// by connecting to the MS symbol server and probing for the file before declaring success and
// showing it to the user.
//@category Import

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.AccessMode;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import pdb.symbolserver.*;

public class GetMSDownloadLinkScript extends GhidraScript {

	private static final String MS_PUBLIC_SYMBOL_SERVER_URL =
		"https://msdl.microsoft.com/download/symbols/";

	@Override
	protected void run() throws Exception {
		SymbolServerService symbolService =
			new SymbolServerService(new SameDirSymbolStore(null), List.of(
				new HttpSymbolServer(URI.create(MS_PUBLIC_SYMBOL_SERVER_URL))));

		File f = askFile("File To Scan", "Select");
		if (f == null) {
			return;
		}

		try (FileByteProvider bp = new FileByteProvider(f, null, AccessMode.READ)) {
			monitor.setMessage("Parsing file " + f.getName());
			PortableExecutable pe = new PortableExecutable(bp, SectionLayout.FILE, false, false);
			NTHeader ntHeader = pe.getNTHeader();
			if (ntHeader != null && ntHeader.getOptionalHeader() != null) {
				int timeDateStamp = ntHeader.getFileHeader().getTimeDateStamp();
				int sizeOfImage = (int) ntHeader.getOptionalHeader().getSizeOfImage();
				println(f + ", timeDateStamp: " + Integer.toHexString(timeDateStamp) +
					", sizeOfImage: " + Integer.toHexString(sizeOfImage));
				SymbolFileInfo symbolFileInfo = SymbolFileInfo.fromValues(f.getName().toLowerCase(),
					Integer.toHexString(timeDateStamp), sizeOfImage);
				List<SymbolFileLocation> findResults =
					symbolService.find(symbolFileInfo, FindOption.of(FindOption.ALLOW_REMOTE),
						monitor);
				if (findResults.isEmpty()) {
					println("Not found on " + MS_PUBLIC_SYMBOL_SERVER_URL);
					return;
				}
				SymbolFileLocation symLoc = findResults.get(0);
				println("Download link: " + symLoc.getLocationStr());
			}
			else {
				printerr("Unrecognized format: " + f);
			}
		}
		catch (IOException e) {
			printerr("Failed to parse file: " + f);
			printerr(e.getMessage());
		}
	}
}
