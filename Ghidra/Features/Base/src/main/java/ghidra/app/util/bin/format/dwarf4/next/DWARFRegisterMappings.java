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
package ghidra.app.util.bin.format.dwarf4.next;

import ghidra.program.model.lang.Register;

import java.util.Collections;
import java.util.Map;

/**
 * Immutable mapping information between DWARF and Ghidra.
 * <p>
 * Use {@link DWARFRegisterMappingsManager} to get an instance for a Program's specific
 * language.
 * <p>
 * The data held in this class is read from DWARF register mapping information contained 
 * in xml files referenced from the language *.ldefs file in an
 * &lt;external_name tool="DWARF.register.mapping.file" name="register_mapping_filename_here"/&gt; 
 * <p>
 * The format is:<p>
 * <pre>
 * &lt;dwarf&gt;
 *   &lt;register_mappings&gt;
 *       &lt;!-- Simple single mapping: --&gt;
 *       &lt;!-- NN == dwarf register number --&gt;
 *       &lt;!-- RegName == Ghidra register name string --&gt;
 *       &lt;!-- &lt;register_mapping dwarf="NN" ghidra="RegName" /&gt; --&gt;
 *       
 *       &lt;!-- Example: --&gt;
 *     &lt;register_mapping dwarf="0" ghidra="r0" /&gt;
 *     
 *       &lt;!-- Single mapping specifying stack pointer: --&gt;
 *       &lt;!-- NN == dwarf register number --&gt;
 *       &lt;!-- RegName == Ghidra register name string --&gt;
 *       &lt;!-- &lt;register_mapping dwarf="NN" ghidra="RegName" stackpointer="true"/&gt; --&gt;
 *       
 *       &lt;!-- Example: --&gt;
 *     &lt;register_mapping dwarf="4" ghidra="ESP" stackpointer="true"/&gt;
 *     
 *       &lt;!-- Multiple mapping: --&gt;
 *       &lt;!-- NN == dwarf register number --&gt;
 *       &lt;!-- XX == number of times to repeat --&gt;
 *       &lt;!-- RegNameYY == Ghidra register name string with a mandatory integer suffix --&gt;
 *       &lt;!-- &lt;register_mapping dwarf="NN" ghidra="RegNameYY" auto_count="XX"/&gt; --&gt;
 *       
 *       &lt;!-- Example, creates mapping from 0..12 to r0..r12: --&gt;
 *     &lt;register_mapping dwarf="0" ghidra="r0" auto_count="12"/&gt;
 *     
 *       &lt;!-- Example, creates mapping from 17..32 to XMM0..XMM15: --&gt;
 *     &lt;register_mapping dwarf="17" ghidra="XMM0" auto_count="16"/&gt;
 *     
 *   &lt;/register_mappings&gt;
 *   
 *     &lt;!-- Call Frame CFA Value: --&gt;
 *   &lt;call_frame_cfa value="NN"/&gt;
 *   
 *     &lt;!-- Use Formal Parameter Storage toggle: --&gt;
 *   &lt;use_formal_parameter_storage/&gt;
 * &lt;/dwarf&gt;
 * </pre>
 */
public class DWARFRegisterMappings {

	public static final DWARFRegisterMappings DUMMY =
		new DWARFRegisterMappings(Collections.emptyMap(), 0, -1, false);

	/*
	 * Maps DWARF register number to Ghidra architecture registers.
	 */
	private final Map<Integer, Register> dwarfRegisterMap;

	private final long callFrameCFA;

	private final int stackPointerIndex;

	private final boolean useFormalParameterStorage;

	public DWARFRegisterMappings(Map<Integer, Register> regmap, long callFrameCFA,
			int stackPointerIndex, boolean useFPS) {
		this.dwarfRegisterMap = regmap;
		this.callFrameCFA = callFrameCFA;
		this.stackPointerIndex = stackPointerIndex;
		this.useFormalParameterStorage = useFPS;
	}

	public Register getGhidraReg(int dwarfRegNum) {
		return dwarfRegisterMap.get(dwarfRegNum);
	}

	public long getCallFrameCFA() {
		return callFrameCFA;
	}

	public int getDWARFStackPointerRegNum() {
		return stackPointerIndex;
	}

	public boolean isUseFormalParameterStorage() {
		return useFormalParameterStorage;
	}

	@Override
	public String toString() {
		return "DWARFRegisterMappings [dwarfRegisterMap=" + dwarfRegisterMap + ", callFrameCFA=" +
			callFrameCFA + ", stackPointerIndex=" + stackPointerIndex +
			", useFormalParameterStorage=" + useFormalParameterStorage + "]";
	}

}
