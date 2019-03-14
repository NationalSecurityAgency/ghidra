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
package ghidra.app.util.bin.format.objc2;

import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public final class ObjectiveC2_Constants {

	/**
	 * The name prefix of all Objective-C 2 sections.
	 */
	private final static String OBJC2_PREFIX                    = "__objc_";

	/** Objective-C 2 category list. */
	public final static String OBJC2_CATEGORY_LIST             = "__objc_catlist";
	/** Objective-C 2 class list. */
	public final static String OBJC2_CLASS_LIST                = "__objc_classlist";
	/** Objective-C 2 class references. */
	public final static String OBJC2_CLASS_REFS                = "__objc_classrefs";
	/** Objective-C 2 constants. */
	public final static String OBJC2_CONST                     = "__objc_const";
	/**  */
	public final static String OBJC2_DATA                      = "__objc_data";
	/**  */
	public final static String OBJC2_IMAGE_INFO                = "__objc_imageinfo";
	/**  */
	public final static String OBJC2_MESSAGE_REFS              = "__objc_msgrefs";
	/** Objective-C 2 non-lazy class list */
	public final static String OBJC2_NON_LAZY_CLASS_LIST       = "__objc_nlclslist";
	/**  */
	public final static String OBJC2_PROTOCOL_LIST             = "__objc_protolist";
	/**  */
	public final static String OBJC2_PROTOCOL_REFS             = "__objc_protorefs";
	/**  */
	public final static String OBJC2_SELECTOR_REFS             = "__objc_selrefs";
	/**  */
	public final static String OBJC2_SUPER_REFS                = "__objc_superrefs";

	/**
	 * Returns a list containing valid Objective-C 2.0 section names.
	 * @return a list containing valid Objective-C 2.0 section names
	 */
	public final static List<String> getObjectiveC2SectionNames() {
		List<String> sectionNames = new ArrayList<String>();
		Field [] declaredFields = ObjectiveC2_Constants.class.getDeclaredFields();
		for (Field field : declaredFields) {
			try {
				String name = (String)field.get(null);
				if (!name.equals(OBJC2_PREFIX) && name.startsWith(OBJC2_PREFIX)) {
					sectionNames.add(name);
				}
			}
			catch (Exception e) {
			}
		}
		sectionNames.add("__data");//not really an Objective-C 2.0 section, but it contains structures used by Objective-C 2.0
		return sectionNames;
	}
	/**
	 * Returns true if this program contains Objective-C 2.
	 * @param program the program to check
	 * @return true if the program contains Objective-C 2.
	 */
	public final static boolean isObjectiveC2(Program program) {
		String format = program.getExecutableFormat();
		if (MachoLoader.MACH_O_NAME.equals(format)) {
			MemoryBlock [] blocks = program.getMemory().getBlocks();
			for (MemoryBlock memoryBlock : blocks) {
				if (memoryBlock.getName().startsWith(OBJC2_PREFIX)) {
					return true;
				}
			}
		}
		return false;
	}

	public final static String NAMESPACE = "objc2";

	public final static String CATEGORY = "/_objc2_";

	public final static CategoryPath CATEGORY_PATH = new CategoryPath(CATEGORY);
}
