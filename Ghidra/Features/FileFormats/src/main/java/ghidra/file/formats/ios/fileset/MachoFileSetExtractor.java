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
package ghidra.file.formats.ios.fileset;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.file.formats.ios.ExtractedMacho;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A class for extracting components from a {@link MachoFileSetFileSystem}
 */
public class MachoFileSetExtractor {

	/**
	 * A footer that gets appended to the end of every extracted component so Ghidra can identify
	 * them and treat them special when imported
	 */
	public static final byte[] FOOTER_V1 =
		"Ghidra Mach-O file set extraction v1".getBytes(StandardCharsets.US_ASCII);

	/**
	 * Gets a {@link ByteProvider} that contains a Mach-O file set entry. The Mach-O's header will
	 * be altered to account for its segment bytes being packed down.   
	 * 
	 * @param provider The Mach-O file set provider
	 * @param providerOffset The offset of the Mach-O file set entry in the given provider
	 * @param fsrl {@link FSRL} to assign to the resulting {@link ByteProvider}
	 * @param monitor {@link TaskMonitor}
	 * @return {@link ByteProvider} containing the bytes of the extracted Mach-O file set entry
	 * @throws MachException If there was an error parsing the Mach-O file set header
	 * @throws IOException If there was an IO-related issue with extracting the Mach-O file set 
	 *   entry
	 * @throws CancelledException If the user cancelled the operation
	 */
	public static ByteProvider extractFileSetEntry(ByteProvider provider, long providerOffset,
			FSRL fsrl, TaskMonitor monitor) throws IOException, MachException, CancelledException {

		ExtractedMacho extractedMacho = new ExtractedMacho(provider, providerOffset,
			new MachHeader(provider, providerOffset, false).parse(), FOOTER_V1, monitor);
		extractedMacho.pack();
		return extractedMacho.getByteProvider(fsrl);
	}
}
