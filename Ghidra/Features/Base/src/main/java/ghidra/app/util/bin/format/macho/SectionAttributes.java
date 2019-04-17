/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.macho;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public final class SectionAttributes {

	/**  24 section attributes */
	public final static int SECTION_ATTRIBUTES_MASK     = 0xffffff00;

	/** Attribute: User setable attributes */
	public final static int SECTION_ATTRIBUTES_USR      = 0xff000000;
	/** Attribute: system setable attributes */
	public final static int SECTION_ATTRIBUTES_SYS      = 0x00ffff00;

	/** Attribute: section contains only true machine instructions */
	public final static int S_ATTR_PURE_INSTRUCTIONS    = 0x80000000;
	/** Attribute: section contains coalesced symbols that are not to be in a ranlib table of contents */
	public final static int S_ATTR_NO_TOC               = 0x40000000;
	/** Attribute: ok to strip static symbols in this section in files with the MH_DYLDLINK flag */
	public final static int S_ATTR_STRIP_STATIC_SYMS    = 0x20000000;
	/** Attribute: section must not be dead-stripped. (see "linking" in xcode2 user guide) */
	public final static int S_ATTR_NO_DEAD_STRIP        = 0x10000000;
	/** Attribute: section must  */
	public final static int S_ATTR_LIVE_SUPPORT         = 0x08000000;
	/** Attribute: Used with i386 code stubs written on by dyld */
	public final static int S_ATTR_SELF_MODIFYING_CODE  = 0x04000000;
	/** Attribute: section contains some machine instructions */
	public final static int S_ATTR_SOME_INSTRUCTIONS    = 0x00000400;
	/** Attribute: section has external relocation entries */
	public final static int S_ATTR_EXT_RELOC            = 0x00000200;
	/** Attribute: section has local relocation entries */
	public final static int S_ATTR_LOC_RELOC            = 0x00000100;

	public final static List<String> getAttributeNames( int attributes ) {
		List<String> list = new ArrayList<String>();
		Field [] fields = Section.class.getDeclaredFields();
		for (Field field : fields) {
			if (field.getName().startsWith("S_ATTR_")) {
				try {
					Integer value = (Integer)field.get(null);
					if ((attributes & value) != 0) {
						list.add(field.getName().substring("S_ATTR_".length()));
					}
				}
				catch (Exception e) {
				}
			}
		}
		return list;
	}
}
