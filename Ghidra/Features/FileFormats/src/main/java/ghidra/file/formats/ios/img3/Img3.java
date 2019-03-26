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
package ghidra.file.formats.ios.img3;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.file.formats.ios.img3.tag.Img3TagFactory;
import ghidra.program.model.data.DataType;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

public class Img3 implements StructConverter {

	private int magic;
	private int size;
	private int dataSize;
	private int checkArea;
	private int identifier;

	private List<AbstractImg3Tag> _tags = new ArrayList<AbstractImg3Tag>();

	public Img3(ByteProvider provider) throws IOException {
		this(new BinaryReader(provider, true));
	}

	public Img3(BinaryReader reader) throws IOException {
		magic       =  reader.readNextInt();
		size        =  reader.readNextInt();
		dataSize    =  reader.readNextInt();
		checkArea = reader.readNextInt();
		identifier  =  reader.readNextInt();

		while (reader.getPointerIndex() < size) {
			long index = reader.getPointerIndex();

			AbstractImg3Tag tag = Img3TagFactory.get(reader);
			_tags.add( tag );

			reader.setPointerIndex(index + tag.getTotalLength());
		}
	}

	public String getMagic() {
		return StringUtilities.toString(magic);
	}
	public int getSize() {
		return size;
	}
	public int getDataSize() {
		return dataSize;
	}
	public int getCheckArea() {
		return checkArea;
	}
	public int getIdentifier() {
		return identifier;
	}

	public List<AbstractImg3Tag> getTags() {
		return _tags;
	}

	public <T> List<T> getTags(Class<T> classType) {
		List<T> tmp = new ArrayList<T>();
		for (AbstractImg3Tag tag : _tags) {
			if (tag.getClass() == classType) {
				tmp.add(classType.cast(tag));
			}
		}
		return tmp;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
