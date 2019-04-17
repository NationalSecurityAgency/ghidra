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

import ghidra.util.Msg;

import java.lang.reflect.Field;


/**
 */
public final class MachHeaderFileTypes {
	/** relocatable object file */
	public final static int MH_OBJECT      = 0x1;
	/** demand paged executable file */
	public final static int MH_EXECUTE     = 0x2;
	/** fixed VM shared library file */
	public final static int MH_FVMLIB      = 0x3;
	/** core file */
	public final static int MH_CORE        = 0x4;
	/** preloaded executable file */
	public final static int MH_PRELOAD     = 0x5;
	/** dynamically bound shared library */
	public final static int MH_DYLIB       = 0x6;
	/** dynamic link editor */
	public final static int MH_DYLINKER    = 0x7;
	/** dynamically bound bundle file */
	public final static int MH_BUNDLE      = 0x8;
	/** shared library stub for static linking only, no section contents */
	public final static int MH_DYLIB_STUB  = 0x9;
	/** linking only, no section contents, companion file with only debug sections */
	public final static int MH_DSYM        = 0xa;
	/** x86_64 kexts */
	public final static int MH_KEXT_BUNDLE = 0xb;

	public final static String getFileTypeName(int fileType) {
		Field [] fields = MachHeaderFileTypes.class.getDeclaredFields();
		for (Field field : fields) {
			if (field.getName().startsWith("MH_")) {
				try {
					Integer value = (Integer)field.get(null);
					if (value == fileType) {
						return field.getName().substring("MH_".length());
					}
				}
				catch (Exception e) {
				    Msg.error(MachConstants.class, "Unexpected Exception: " + e.getMessage(), e);
				}
			}
		}
		return "Unrecognized file type: 0x"+Integer.toHexString(fileType);
	}

	public final static String getFileTypeDescription(int fileType) {
		switch (fileType) {
			case MH_OBJECT:       return "Relocatable Object File";
			case MH_EXECUTE:      return "Demand Paged Executable File";
			case MH_FVMLIB:       return "Fixed VM Shared Library File";
			case MH_CORE:         return "Core File";
			case MH_PRELOAD:      return "Preloaded Executable File";
			case MH_DYLIB:        return "Dynamically Bound Shared Library";
			case MH_DYLINKER:     return "Dynamic Link Editor";
			case MH_BUNDLE:       return "Dynamically Bound Bundle File";
			case MH_DYLIB_STUB:   return "Shared Library Stub for Static Linking Only";
			case MH_DSYM:         return "Companion file with only debug sections";
			case MH_KEXT_BUNDLE:  return "x86 64 Kernel Extension";
		}
		return "Unrecognized file type: 0x"+Integer.toHexString(fileType);
	}
}
