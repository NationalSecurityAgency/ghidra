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
package ghidra.file.formats.android.art;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.file.formats.android.oat.OatConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class ArtAnalyzer extends FileFormatAnalyzer {

	@Override
	public String getName() {
		return "Android ART Header Format";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Analyzes the Android ART information in this program.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		return ArtConstants.isART(program)
		//HACK:
		//Make analyzer appear after ART is merged with OAT program
		//Currently, analyzers will not recognize the new ART block being added
			|| OatConstants.isOAT(program);
	}

	@Override
	public boolean isPrototype() {
		return true;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		Address address = ArtConstants.findART(program);

		if (address == null) {//ART does not exist so quit, could be OAT
			return false;
		}

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());

		try {
			ArtHeader header = ArtFactory.newArtHeader(reader);

			DataType headerDataType = header.toDataType();

			//only set "image base" when ART header not defined at "image begin"
			//---this really only opens when ART is "added to" OAT program
			Address imageBase = toAddr(program, header.getImageBegin());

			if (BinaryLoader.BINARY_NAME.equals(program.getExecutableFormat())) {
				program.setImageBase(imageBase, true);
				createData(program, imageBase, headerDataType);
			}
			else {
				createData(program, address, headerDataType);
			}

			header.markup(program, monitor);

			return true;
		}
		catch (UnsupportedArtVersionException e) {
			log.appendException(e);
		}
		catch (Exception e) {
			throw e;
		}
		return false;
	}

}
