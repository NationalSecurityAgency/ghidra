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
 * Exception handling data decoding formats.
 * See the <a href="http://refspecs.freestandards.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html">Linux Standard Base DWARF extensions specification</a> for details.
 */
public enum DwarfEHDataDecodeFormat {
	// @formatter:off
	DW_EH_PE_absptr(0x00), DW_EH_PE_uleb128(0x01),

	DW_EH_PE_udata2(0x02), DW_EH_PE_udata4(0x03), DW_EH_PE_udata8(0x04),

	DW_EH_PE_signed(0x08), DW_EH_PE_sleb128(0x09),

	DW_EH_PE_sdata2(0x0a), DW_EH_PE_sdata4(0x0b), DW_EH_PE_sdata8(0x0c),

	DW_EH_PE_omit(0x0f);

	// @formatter:on

	private final int code;

	private DwarfEHDataDecodeFormat(int code) {
		this.code = code;
	}

	/**
	 * Get the code for this decode format.
	 * @return the identifier code
	 */
	public int getCode() {
		return code;
	}

	/**
	 * Gets the exception handling decode format for the indicated code.
	 * @param code the code
	 * @return the decode format
	 */
	public static DwarfEHDataDecodeFormat valueOf(int code) {
		for (DwarfEHDataDecodeFormat mod : DwarfEHDataDecodeFormat.values()) {
			if (mod.code == code) {
				return mod;
			}
		}
		return null;
	}

}
