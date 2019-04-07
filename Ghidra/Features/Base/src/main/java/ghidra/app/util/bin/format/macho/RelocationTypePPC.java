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

public enum RelocationTypePPC {
	PPC_RELOC_VANILLA,
	PPC_RELOC_PAIR,
	PPC_RELOC_BR14,
	PPC_RELOC_BR24,
	PPC_RELOC_HI16,
	PPC_RELOC_LO16,
	PPC_RELOC_HA16,
	PPC_RELOC_LO14,
	PPC_RELOC_SECTDIFF,
	PPC_RELOC_PB_LA_PTR,
	PPC_RELOC_HI16_SECTDIFF,
	PPC_RELOC_LO16_SECTDIFF,
	PPC_RELOC_HA16_SECTDIFF,
	PPC_RELOC_JBSR,
	PPC_RELOC_LO14_SECTDIFF,
	PPC_RELOC_LOCAL_SECTDIFF;

}
