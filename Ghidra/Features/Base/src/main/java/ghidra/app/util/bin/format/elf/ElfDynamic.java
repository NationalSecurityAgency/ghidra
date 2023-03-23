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
package ghidra.app.util.bin.format.elf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.StringUtilities;

/**
 * A class to represent the Elf<code>32</code>_Dyn data structure.
 * 
 * <pre><code>
 * typedef  int32_t  Elf32_Sword;
 * typedef uint32_t  Elf32_Word;
 * typedef uint32_t  Elf32_Addr;
 * 
 *  typedef struct {
 *      Elf32_Sword     d_tag;
 *      union {
 *          Elf32_Word  d_val;
 *          Elf32_Addr  d_ptr;
 *      } d_un;
 *  } Elf32_Dyn;
 * 
 * typedef   int64_t  Elf64_Sxword;
 * typedef  uint64_t  Elf64_Xword;
 * typedef  uint64_t  Elf64_Addr;
 * 
 * typedef struct {
 *     Elf64_Sxword	   d_tag;     //Dynamic entry type
 *     union {
 *         Elf64_Xword d_val;     //Integer value
 *         Elf64_Addr  d_ptr;     //Address value
 *     } d_un;
 * } Elf64_Dyn;
 * 
 * </code></pre>
 */
public class ElfDynamic {

	private ElfHeader elf;

	private int d_tag;
    private long d_val;

	public ElfDynamic(BinaryReader reader, ElfHeader elf)
			throws IOException {
		this.elf = elf;
		if (elf.is32Bit()) {
			d_tag = reader.readNextInt();
			d_val = Integer.toUnsignedLong(reader.readNextInt());
        }
        else {
			d_tag = (int) reader.readNextLong();
            d_val = reader.readNextLong();
        }
    }

    /**
     * Constructs a new ELF dynamic with the specified tag and value.
     * @param tag     the tag (or type) of this dynamic
     * @param value   the value (or pointer) of this dynamic
     * @param elf     the elf header
     */
	public ElfDynamic(int tag, long value, ElfHeader elf) {
        this.d_tag = tag;
        this.d_val = value;
		this.elf = elf;
    }

    /**
     * Constructs a new ELF dynamic with the specified (enum) tag and value.
     * @param tag     the (enum) tag (or type) of this dynamic
     * @param value   the value (or pointer) of this dynamic
     * @param elf     the elf header
     */
	public ElfDynamic(ElfDynamicType tag, long value, ElfHeader elf) {
		this(tag.value, value, elf);
    }

    /**
     * Returns the value that controls the interpretation of the 
     * the d_val and/or d_ptr.
     * @return the tag (or type) of this dynamic
     */
	public int getTag() {
        return d_tag;
    }

    /**
     * Returns the enum value that controls the interpretation of the 
     * the d_val and/or d_ptr (or null if unknown).
     * @return the enum tag (or type) of this dynamic or null if unknown
     */
	public ElfDynamicType getTagType() {
		return elf.getDynamicType(d_tag);
	}

    /**
     * Returns the object whose integer values represent various interpretations.
     * For example, if d_tag == DT_SYMTAB, then d_val holds the address of the symbol table.
     * But, if d_tag == DT_SYMENT, then d_val holds the size of each symbol entry.
     * @return the Elf32_Word object represent integer values with various interpretations
     */
    public long getValue() {
        return d_val;
    }

    /**
     * A convenience method for getting a string representing the d_tag value.
     * For example, if d_tag == DT_SYMTAB, then this method returns "DT_SYMTAB".
     * @return a string representing the d_tag value
     */
	public String getTagAsString() {
		ElfDynamicType tagType = getTagType();
		if (tagType != null) {
			return tagType.name;
		}
		return "DT_0x" + StringUtilities.pad(Integer.toHexString(d_tag), '0', 8);
	}

	@Override
	public String toString() {
		return getTagAsString();
	}

    /**
	 * @return the size in bytes of this object.
	 */
	public int sizeof() {
		return elf.is32Bit() ? 8 : 16;
    }

}

