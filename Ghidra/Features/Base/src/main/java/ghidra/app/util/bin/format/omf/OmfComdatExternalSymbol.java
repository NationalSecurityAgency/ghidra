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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

public class OmfComdatExternalSymbol extends OmfExternalSymbol {
	
	public record ExternalLookup(int nameIndex, int type) {}
	protected List<ExternalLookup> externalLookups = new ArrayList<>();

	public OmfComdatExternalSymbol(BinaryReader reader) throws IOException {
		super(false);
		readRecordHeader(reader);

		long max = reader.getPointerIndex() + getRecordLength() - 1;
		while (reader.getPointerIndex() < max) {
			int nameIndex = OmfRecord.readIndex(reader);
			int type = OmfRecord.readIndex(reader);
			externalLookups.add(new ExternalLookup(nameIndex, type));
		}

		readCheckSumByte(reader);
	}

	public void loadNames(List<String> nameList) {
		for (ExternalLookup ext : externalLookups) {
			String name = nameList.get(ext.nameIndex - 1);
			symbols.add(new OmfSymbol(name, ext.type, 0, 0, 0));
		}
	}
}
