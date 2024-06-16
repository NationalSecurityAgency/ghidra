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
package ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.Constants;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum;
import ghidra.program.model.listing.Program;

public class PEUtil {

	static public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		if (format.equals(PeLoader.PE_NAME)) {
			return true;
		}
		if (format.equals(BinaryLoader.BINARY_NAME)) {
			MemoryByteProvider mbp =
				MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false);
			try {
				BinaryReader reader = new BinaryReader(mbp, true/*LittleEndian*/);
				DOSHeader dosHeader = new DOSHeader(reader);
				if (dosHeader.e_magic() == DOSHeader.IMAGE_DOS_SIGNATURE) {
					int peHeaderStartIndex = dosHeader.e_lfanew();
					int peMagicNumber = reader.readInt(peHeaderStartIndex);
					if (peMagicNumber == Constants.IMAGE_NT_SIGNATURE) {
						return true;
					}
				}
			}
			catch (IOException e) {
				// ignore
			}
		}
		return false;
	}

	static public boolean isVisualStudioOrClangPe(Program program) {
		return program.getExecutableFormat().equals(PeLoader.PE_NAME) &&
			(program.getCompiler().equals(CompilerEnum.VisualStudio.toString()) ||
				program.getCompiler().equals(CompilerEnum.Clang.toString()));
	}

}
