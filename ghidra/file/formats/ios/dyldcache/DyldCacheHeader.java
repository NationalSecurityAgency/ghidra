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
package ghidra.file.formats.ios.dyldcache;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class DyldCacheHeader implements StructConverter {

	private byte []  version;
	private int      baseAddressOffset;
	private int      unknown;
	private int      startAddress;
	private int      libraryCount;
	private long     dyldAddress;

	private BinaryReader _reader;
	private long _baseAddress;
	private List<DyldCacheData> _list = new ArrayList<DyldCacheData>();
	private DyldArchitecture _architecture;

	public DyldCacheHeader(BinaryReader reader) throws IOException {
		_reader  =  reader;

		version            =  reader.readNextByteArray( 16 );
		baseAddressOffset  =  reader.readNextInt();
		unknown            =  reader.readNextInt();
		startAddress       =  reader.readNextInt();
		libraryCount       =  reader.readNextInt();
		dyldAddress        =  reader.readNextLong();

		_baseAddress  =  reader.readLong( baseAddressOffset & 0xffffffffL );

		_architecture = DyldArchitecture.getArchitecture( new String( version ).trim() );
	}

	public void parse(TaskMonitor monitor) throws IOException {
		_reader.setPointerIndex( startAddress );

		for (int i = 0 ; i < libraryCount ; ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			DyldCacheData data = new DyldCacheData( _reader );
			_list.add( data );
		}
	}

	public byte [] getVersion() {
		return version;
	}
	public int getBaseAddressOffset() {
		return baseAddressOffset;
	}
	public long getBaseAddress() {
		return _baseAddress;
	}
	public int getUnknown() {
		return unknown;
	}
	public int getStartAddress() {
		return startAddress;
	}
	public int getLibraryCount() {
		return libraryCount;
	}
	public long getDyldAddress() {
		return dyldAddress;
	}

	public List<DyldCacheData> getDataList() {
		return _list;
	}

	public DyldArchitecture getArchitecture() {
		return _architecture;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
