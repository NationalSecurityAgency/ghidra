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
package ghidra.app.util.bin.format.macho.commands.codesignature;

import static ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureConstants.*;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * Class to parse Code Signature blobs
 */
public class CodeSignatureBlobParser {

	/**
	 * Parses a new Code Signature blob
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a Code Signature blob
	 * @return A new Code Signature blob
	 * @throws IOException if there was an IO-related error parsing the blob
	 */
	public static CodeSignatureGenericBlob parse(BinaryReader reader) throws IOException {
		int magic = reader.peekNextInt();
		return switch (magic) {
			case CSMAGIC_EMBEDDED_SIGNATURE -> new CodeSignatureSuperBlob(reader);
			case CSMAGIC_CODEDIRECTORY -> new CodeSignatureCodeDirectory(reader);
			// TODO: Handle more blob types
			default -> new CodeSignatureGenericBlob(reader);
		};
	}
}
