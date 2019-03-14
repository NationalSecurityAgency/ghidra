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
package ghidra.pcodeCPort.slghsymbol;

public enum symbol_type {
	space_symbol,
	token_symbol,
	userop_symbol,
	value_symbol,
	valuemap_symbol,
	name_symbol,
	varnode_symbol,
	varnodelist_symbol,
	operand_symbol,
	start_symbol,  // inst_start, inst_ref, inst_def
	end_symbol,    // inst_next
	subtable_symbol,
	macro_symbol,
	section_symbol,
	bitrange_symbol,
	context_symbol,
	epsilon_symbol,
	label_symbol,
	dummy_symbol
}
