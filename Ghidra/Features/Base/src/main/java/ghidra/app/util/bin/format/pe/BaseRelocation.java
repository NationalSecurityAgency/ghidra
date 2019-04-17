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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the <code>IMAGE_BASE_RELOCATION</code>
 * data structure defined in <b><code>winnt.h</code></b>.
 * <pre>
 * typedef struct _IMAGE_BASE_RELOCATION {
 *     DWORD   VirtualAddress;
 *     DWORD   SizeOfBlock;
 * //  WORD    TypeOffset[1];
 * } IMAGE_BASE_RELOCATION;
 * typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
 * </pre>
 * 
 * 
 */
public class BaseRelocation implements StructConverter, ByteArrayConverter {
	/**
	 * The name to use when converting into a structure data type.
	 */
    public final static String NAME = "IMAGE_BASE_RELOCATION";
    /**
     * The size of the <code>IMAGE_BASE_RELOCATION</code> in bytes.
     */
    public final static int IMAGE_SIZEOF_BASE_RELOCATION = 8;

	public final static int IMAGE_REL_BASED_NOOP             =  0;
    public final static int IMAGE_REL_BASED_ABSOLUTE          =  0;
    public final static int IMAGE_REL_BASED_HIGH              =  1;
    public final static int IMAGE_REL_BASED_LOW               =  2;
    public final static int IMAGE_REL_BASED_HIGHLOW           =  3;
    public final static int IMAGE_REL_BASED_HIGHADJ           =  4;

    public final static int IMAGE_REL_BASED_MIPS_JMPADDR      =  5;
    public final static int IMAGE_REL_BASED_SECTION           =  6;
    public final static int IMAGE_REL_BASED_REL32             =  7;
    public final static int IMAGE_REL_BASED_MIPS_JMPADDR16    =  9;
    public final static int IMAGE_REL_BASED_IA64_IMM64        =  9;
    public final static int IMAGE_REL_BASED_DIR64             = 10;
    public final static int IMAGE_REL_BASED_HIGH3ADJ          = 11;

	/**
	 * Names of the available base relocations.
	 */
    public final static String [] TYPE_STRINGS = {
                        "ABSOLUTE",             // 0
                        "HIGH",                 // 1
                        "LOW",                  // 2
                        "HIGHLOW",              // 3
                        "HIGHADJ",              // 4
                        "MIPS_JMPADDR",         // 5
                         "???6",
                         "???7",
                         "???8",
                        "IA64_IMM64",           // 9
                        "DIR64",                // 10
    };

    private int virtualAddress;
    private int sizeOfBlock;
    private List<TypeOffset> typeOffsetList = new ArrayList<TypeOffset>();

    static BaseRelocation createBaseRelocation(
            FactoryBundledWithBinaryReader reader, int index)
            throws IOException {
        BaseRelocation baseRelocation = (BaseRelocation) reader.getFactory().create(BaseRelocation.class);
        baseRelocation.initBaseRelocation(reader, index);
        return baseRelocation;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public BaseRelocation() {}

    private void initBaseRelocation(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        virtualAddress = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
        sizeOfBlock    = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
        if (virtualAddress < 0) return;
        if (sizeOfBlock < 0 || sizeOfBlock > NTHeader.MAX_SANE_COUNT) return;

		int len = (sizeOfBlock-IMAGE_SIZEOF_BASE_RELOCATION)/BinaryReader.SIZEOF_SHORT;

		for (int i = 0 ; i < len ; ++i) {
			short typeOffset = reader.readShort(index);
			index += BinaryReader.SIZEOF_SHORT;

			typeOffsetList.add(new TypeOffset(typeOffset));
        }
    }

	BaseRelocation(int virtualAddress) {
		this.virtualAddress = virtualAddress;
		this.sizeOfBlock = IMAGE_SIZEOF_BASE_RELOCATION;
	}

	/**
	 * Adds a relocation to this base relocation block.
	 * @param type   the relocation type
	 * @param offset the relocation offset
	 */
	public void addRelocation(int type, int offset) {
		typeOffsetList.add(new TypeOffset(type, offset));
		sizeOfBlock += BinaryReader.SIZEOF_SHORT;
	}

    /**
     * Returns the base address of the relocations in this block.
     * @return the base address of the relocations in this block
     */
    public int getVirtualAddress() {
        return virtualAddress;
    }

    /**
     * Returns the size (in bytes) of this relocation block.
     * @return the size (in bytes) of this relocation block
     */
    public int getSizeOfBlock() {
        return sizeOfBlock;
    }

    /**
     * Returns the number of relocation in this block.
     * @return the number of relocation in this block
     */
    public int getCount() {
        return typeOffsetList.size();
    }

    /**
     * Returns the lower 12 bits of the offset.
     *
     * @param index the ith relocation
     * @return int the offset of the relocation
     */
    public int getOffset(int index) {
        return typeOffsetList.get(index).offset;
    }

	/**
	 * Returns the upper 4 bits of the offset.
	 *
	 * @param index the ith relocation
	 * @return int the type of the relocation
,	 */
    public int getType(int index) {
        return typeOffsetList.get(index).type;
    }

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(NAME, 0);

        struct.add(DWORD,"VirtualAddress",null);
        struct.add(DWORD,"SizeOfBlock",null);
        struct.add(new ArrayDataType(WORD, typeOffsetList.size(), WORD.getLength()),"TypeOffset",null);

        struct.setCategoryPath(new CategoryPath("/PE"));

        return struct;
    }

	/**
	 * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
	 */
	public byte[] toBytes(DataConverter dc) {
		byte [] bytes = new byte[sizeOfBlock];
		int pos = 0;
		dc.getBytes(virtualAddress, bytes, pos);
		pos += BinaryReader.SIZEOF_INT;
		dc.getBytes(sizeOfBlock, bytes, pos);
		pos += BinaryReader.SIZEOF_INT;
		for (int i = 0; i < typeOffsetList.size(); i++) {
			short typeOffset = typeOffsetList.get(i).typeOffset;
			dc.getBytes(typeOffset, bytes, pos);
			pos += BinaryReader.SIZEOF_SHORT;
		}
		return bytes;
	}

	private class TypeOffset {
		short typeOffset;
		int type;
		int offset;

		TypeOffset(short typeOffset) {
			this.typeOffset = typeOffset;
			this.type = ((typeOffset & 0xF000) >> 12) & 0x000F;
			this.offset = typeOffset & 0x0FFF;
		}

		TypeOffset(int type, int offset) {
			this.typeOffset = (short)(((type&0xf) << 12) | (offset & 0xfff));
			this.type = type;
			this.offset = offset;
		}
	}
}
