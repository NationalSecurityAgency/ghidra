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
package ghidra.app.plugin.exceptionhandlers.gcc;

/**
 * An application mode for encoded exception handling data.
 * See the <a href="http://refspecs.freestandards.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html">Linux Standard Base DWARF extensions specification</a> for details.
 */
public enum DwarfEHDataApplicationMode {
	// @formatter:off
	DW_EH_PE_absptr(0x00),

	DW_EH_PE_pcrel(0x10),

	DW_EH_PE_texrel(0x20),

	DW_EH_PE_datarel(0x30),

	DW_EH_PE_funcrel(0x40),

	DW_EH_PE_aligned(0x50),

	DW_EH_PE_indirect(0x80),

	DW_EH_PE_omit(0xf0);
	// @formatter:on

	private final int code;

	private DwarfEHDataApplicationMode(int code) {
		this.code = code;
	}

	/**
	 * Determines the data application mode for the indicated code.
	 * 
	 * @param code a code that indicates a data application mode
	 * @return the data application mode or null if the code isn't valid
	 */
	public static DwarfEHDataApplicationMode valueOf(int code) {
		for (DwarfEHDataApplicationMode mod : DwarfEHDataApplicationMode.values()) {
			if (mod.code == code) {
				return mod;
			}
		}
		return null;
	}

}
