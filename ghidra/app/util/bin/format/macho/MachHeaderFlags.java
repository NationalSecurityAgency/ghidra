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
package ghidra.app.util.bin.format.macho;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * Constants for the flags field of the mach_header
 */
public final class MachHeaderFlags {

	/**
	 * the object file has no undefined references.
	 */
	public final static int MH_NOUNDEFS                 = 0x1;
	/**
	 * the object file is the output of an incremental 
	 * link against a base file and can't be link 
	 * edited again.
	 */
	public final static int MH_INCRLINK                 = 0x2;
	/**
	 * the object file is input for the dynamic 
	 * linker and can't be staticly link edited again.
	 */
	public final static int MH_DYLDLINK                 = 0x4;
	/**
	 * the object file's undefined references 
	 * are bound by the dynamic linker when loaded.
	 */
	public final static int MH_BINDATLOAD               = 0x8;
	/**
	 * the file has its dynamic undefined references 
	 * prebound.
	 */
	public final static int MH_PREBOUND                 = 0x10;
	/**
	 * the file has its read-only and read-write 
	 * segments split.
	 */
	public final static int MH_SPLIT_SEGS               = 0x20;
	/**
	 * the shared library init routine is to be 
	 * run lazily via catching memory faults to its 
	 * writeable segments (obsolete).
	 */
	public final static int MH_LAZY_INIT                = 0x40;
	/**
	 * the image is using two-level name space bindings.
	 */
	public final static int MH_TWOLEVEL                 = 0x80;
	/**
	 * the executable is forcing all images to use 
	 * flat name space bindings.
	 */
	public final static int MH_FORCE_FLAT               = 0x100;
	/**
	 * this umbrella guarantees no multiple defintions 
	 * of symbols in its sub-images so the two-level 
	 * namespace hints can always be used.
	 * */
	public final static int MH_NOMULTIDEFS              = 0x200;
	/**
	 * do not have dyld notify the prebinding 
	 * agent about this executable.
	 */
	public final static int MH_NOFIXPREBINDING          = 0x400;
	/**
	 * the binary is not prebound but can have 
	 * its prebinding redone. only used when 
	 * MH_PREBOUND is not set.
	 */
	public final static int MH_PREBINDABLE              = 0x800;
	/**
	 * indicates that this binary binds to all 
	 * two-level namespace modules of its dependent 
	 * libraries. only used when MH_PREBINDABLE and 
	 * MH_TWOLEVEL are both set.
	 */
	public final static int MH_ALLMODSBOUND             = 0x1000; 
	/**
	 * safe to divide up the sections into 
	 * sub-sections via symbols for dead code 
	 * stripping.
	 */
	public final static int MH_SUBSECTIONS_VIA_SYMBOLS  = 0x2000;
	/**
	 * the binary has been canonicalized via the unprebind operation.
	 */
	public final static int MH_CANONICAL                = 0x4000;
	/**
	 * the final linked image contains external weak symbols.
	 */
	public final static int MH_WEAK_DEFINES             = 0x8000;
	/**
	 * the final linked image uses weak symbols.
	 */
	public final static int MH_BINDS_TO_WEAK            = 0x10000;
	/**
	 * when this bit is set, all stacks in the task 
	 * will be given stack execution privilege.
	 * only used in MH_EXECUTE filetypes.
	 */
	public final static int MH_ALLOW_STACK_EXECUTION    = 0x20000;
	/**
	 * When this bit is set, the binary declares it is safe for use in
	 * processes with uid zero
	 */
	public final static int MH_ROOT_SAFE                 = 0x40000;
	/**
	 * When this bit is set, the binary declares it is safe for use in
	 * processes when issetugid() is true
	 */
	public final static int MH_SETUID_SAFE               = 0x80000;
	/**
	 * When this bit is set on a dylib, the static linker does not need to
	 * examine dependent dylibs to see if any are re-exported
	 */
	public final static int MH_NO_REEXPORTED_DYLIBS      = 0x100000;
	/**
	 * When this bit is set, the OS will load the main executable at a
	 * random address.  Only used in MH_EXECUTE filetypes.
	 */
	public final static int MH_PIE                       = 0x200000;
	/**
	 * Only for use on dylibs. 
	 * When linking against a dylib that
	 * has this bit set, the static linker will automatically not create a
	 * LC_LOAD_DYLIB load command to the
	 * dylib if no symbols are being referenced from the dylib.
	 */
	public final static int MH_DEAD_STRIPPABLE_DYLIB    = 0x400000;
	/**
	 * Contains a section of type S_THREAD_LOCAL_VARIABLES.
	 */
	public final static int MH_HAS_TLV_DESCRIPTORS      = 0x800000;
	/**
	 * When this bit is set, the OS will run the main executable
	 * with a non-executable heap even on platforms ( e.g., i386 )
	 * that don't require it.
	 * Only used in MH_EXECUTE file types.
	 */
	public final static int MH_NO_HEAP_EXECUTION        = 0x1000000;
	/**
	 * 
	 */
	public final static int MH_APP_EXTENSION_SAFE        = 0x2000000;

	/**
	 * Returns string representation of the flag values.
	 */
	public final static List<String> getFlags(int flags) {
		List<String> list = new ArrayList<String>();
		Field [] fields = MachHeaderFlags.class.getDeclaredFields();
		for (Field field : fields) {
			if (field.getName().startsWith("MH_")) {
				try {
					Integer value = (Integer)field.get(null);
					if ((flags & value) != 0) {
						list.add(field.getName().substring("MH_".length()));
					}
				}
				catch (Exception e) {
				}
			}
		}
		return list;
	}
}
