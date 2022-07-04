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
package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.ARM_ElfExtension;
import ghidra.program.model.address.Address;

class ARM_ElfRelocationContext extends ElfRelocationContext {

	private final boolean applyPcBiasToRelativeRelocations;

	protected ARM_ElfRelocationContext(ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			ElfRelocationTable relocationTable,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, relocationTable, symbolMap);

		applyPcBiasToRelativeRelocations =
			loadHelper.getOption(ARM_ElfExtension.APPLY_PC_BIAS_TO_RELATIVE_RELOCATIONS_OPTION_NAME,
				ARM_ElfExtension.APPLY_PC_BIAS_TO_RELATIVE_RELOCATIONS_DEFAULT);
	}

	/**
	 * Get the appropriate PC Bias value which should be applied to the computed relocation value.
	 * This method and related option is intended as a work around for differences in how tool-chain
	 * and associated loaders handle the PC Bias and if they factor it into the addend or not.
	 * Within Ghidra, the default is to assume the PC Bias is not factored into the relocation addend
	 * with the {@link ARM_ElfExtension#APPLY_PC_BIAS_TO_RELATIVE_RELOCATIONS_OPTION_NAME} option
	 * being true.
	 * <p>
	 * Example as to how this PC Bias value factors into relocation value computation:
	 * <pre>
	 *    value = (symbolValue + addend) - (relocAddr + pcBias)
	 * </pre>
	 * Within the Sleigh language this bias may be reflected by:
	 * <pre>
	 * ARM:
	 *    (inst_start + 8) or (inst_next + 4)
	 * Thumb (either 16-bit or 32-bit forms): 
	 *    (inst_start + 4)
	 * </pre>
	 * @param isThumb true if Thumb instruction, false if ARM
	 * @return PC Bias value to be applied
	 */
	int getPcBias(boolean isThumb) {
		if (applyPcBiasToRelativeRelocations) {
			return isThumb ? 4 : 8;
		}
		return 0;
	}

}
