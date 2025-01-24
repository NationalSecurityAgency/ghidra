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
package ghidra.app.util.bin.format.omf.omf51;

import static ghidra.app.util.bin.format.omf.omf51.Omf51RecordTypes.*;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.omf.*;
import ghidra.app.util.bin.format.omf.omf166.Omf166RecordTypes;
import ghidra.app.util.bin.format.omf.omf166.Omf166DepList;

/**
 * A class for reading/creating OMF-51 records
 */
public class Omf51RecordFactory extends AbstractOmfRecordFactory {

	/**
	 * Creates a new {@link Omf51RecordFactory}
	 * 
	 * @param provider The {@link ByteProvider} that contains the records
	 */
	public Omf51RecordFactory(ByteProvider provider) {
		super(new BinaryReader(provider, true));
	}

	@Override
	public OmfRecord readNextRecord() throws IOException, OmfException {
		int type = Byte.toUnsignedInt(reader.peekNextByte());
		OmfRecord record = switch (type) {
			case ModuleHDR:
				yield new Omf51ModuleHeader(reader);
			case ModuleEND:
				yield new Omf51ModuleEnd(reader);
			case Omf166RecordTypes.DEPLST:
				yield new Omf166DepList(reader);
			case Content:
			case Fixup:
			case SegmentDEF:
			case ScopeDEF:
			case DebugItem:
			case PublicDEF:
			case ExternalDEF:
			case LibModLocs:
			case LibModNames:
			case LibDictionary:
			case LibHeader:
				yield new OmfUnsupportedRecord(reader, Omf51RecordTypes.class);
			default:
				yield new OmfUnknownRecord(reader);
		};

		record.parseData();
		return record;
	}

	@Override
	public List<Integer> getStartRecordTypes() {
		return List.of(ModuleHDR, Omf166RecordTypes.DEPLST);
	}

	@Override
	public int getEndRecordType() {
		return ModuleEND;
	}

}
