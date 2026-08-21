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

import ghidra.app.util.bin.format.omf.OmfUtils;

/**
 * OMF-51 record types
 * 
 * @see <a href="https://turbo51.com/documentation/omf-51-object-module-format">OMF-51 Object Module Format</a> 
 */
public class Omf51RecordTypes {

	public final static int ModuleHDR = 0x02;
	public final static int ModuleEND = 0x04;
	public final static int Content = 0x06;
	public final static int Fixup = 0x08;
	public final static int SegmentDEF = 0x0e;
	public final static int ScopeDEF = 0x10;
	public final static int DebugItem = 0x12;
	public final static int PublicDEF = 0x16;
	public final static int ExternalDEF = 0x18;
	public final static int LibModLocs = 0x26;
	public final static int LibModNames = 0x28;
	public final static int LibDictionary = 0x2a;
	public final static int LibHeader = 0x2c;

	// Record types with names ending in "Keil", which are produced by ARM Keil's
	// 8051 tooling, are only slight variants of the similarly-named record types in the Intel spec.
	public final static int KeilContent = Content + 1;
	public final static int KeilFixup = Fixup + 1;
	public final static int KeilSegmentDEF = SegmentDEF + 1;
	public final static int KeilScopeDEF = ScopeDEF + 1;
	public final static int KeilPublicDEF = PublicDEF + 1;
	public final static int KeilExternalDEF = ExternalDEF + 1;
	public final static int KeilDebugItemOBJ = 0x22;         // Keil debug items, in linker output format
	public final static int KeilDebugItemSRC = 0x23;         // Keil debug item, in compiler output format
	public final static int KeilModuleSourceName = 0x24;     // Name of the current module's source file
	public final static int KeilSourceBrowserFiles = 0x61;   // Sequence of source filenames, for Keil debugger's source browser

	// The three type values 0x62, 0x63, and 0x64, which are produced by ARM Keil's 8051 toolchain,
	// contain data that is used for source-level debugging in the company's uVision IDE--such 
	// information as function prototypes, struct definitions, function variable names and types,
	// etc. As more is learned about their content, more descriptive names could be considered.
	public final static int KeilDebugData62 = 0x62;
	public final static int KeilDebugData63 = 0x63;
	public final static int KeilDebugData64 = 0x64;

	/**
	 * Gets the name of the given record type
	 * 
	 * @param type The record type
	 * @return The name of the given record type
	 */
	public final static String getName(int type) {
		return OmfUtils.getRecordName(type, Omf51RecordTypes.class);
	}
}
