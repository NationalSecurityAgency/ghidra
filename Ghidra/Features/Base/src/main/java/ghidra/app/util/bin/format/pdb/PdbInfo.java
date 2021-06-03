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
package ghidra.app.util.bin.format.pdb;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.framework.options.Options;

/**
 * Bag of information about a Pdb symbol file, usually extracted from information present in a PE
 * binary.
 * 
 */
public interface PdbInfo {

	/**
	 * Read either a {@link PdbInfoCodeView} object or a {@link PdbInfoDotNet} object
	 * from the BinaryReader of a PE binary.
	 * 
	 * @param reader BinaryReader
	 * @param offset position of the debug info
	 * @return new PdbInfoCodeView or PdbInfoDotNet object
	 * @throws IOException if error
	 */
	public static PdbInfo read(BinaryReader reader, long offset) throws IOException {
		if (PdbInfoCodeView.isMatch(reader, offset)) {
			return PdbInfoCodeView.read(reader, offset);
		}
		if (PdbInfoDotNet.isMatch(reader, offset)) {
			return PdbInfoDotNet.read(reader, offset);
		}
		return null;
	}

	/**
	 * Returns true if this instance is valid.
	 * 
	 * @return boolean true if valid (magic signature matches and fields have valid data)
	 */
	boolean isValid();

	/**
	 * Writes the various PDB info fields to a program's options.
	 * 
	 * @param options Options of a Program to write to
	 */
	void serializeToOptions(Options options);

}
