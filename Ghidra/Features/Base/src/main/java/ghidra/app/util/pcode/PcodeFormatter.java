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
package ghidra.app.util.pcode;

import java.util.*;

import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public interface PcodeFormatter<T> {
	/**
	 * Format the p-code ops
	 * 
	 * @param language the language generating the p-code
	 * @param pcodeOps the p-code ops
	 * @return the formatted result
	 */
	default T formatOps(Language language, List<PcodeOp> pcodeOps) {
		return formatOps(language, language.getAddressFactory(), pcodeOps);
	}

	/**
	 * Format the pcode ops with a specified {@link AddressFactory}.  For use when the 
	 * pcode ops can reference program-specific address spaces.
	 * 
	 * @param language the language generating the p-code
	 * @param addrFactory  addressFactory to use when generating pcodeop templates
	 * @param pcodeOps p-code ops to format
	 * @return the formatted result
	 * 
	 */
	default T formatOps(Language language, AddressFactory addrFactory, List<PcodeOp> pcodeOps) {
		return formatTemplates(language, getPcodeOpTemplates(addrFactory, pcodeOps));
	}

	/**
	 * Format the p-code op templates
	 * 
	 * @param language the language generating the p-code
	 * @param pcodeOpTemplates the templates
	 * @return the formatted result
	 */
	T formatTemplates(Language language, List<OpTpl> pcodeOpTemplates);

	/**
	 * Convert flattened p-code ops into templates.
	 * 
	 * @param addrFactory the language's address factory
	 * @param pcodeOps the p-code ops to convert
	 * @return p-code op templates
	 */
	public static List<OpTpl> getPcodeOpTemplates(AddressFactory addrFactory,
			List<PcodeOp> pcodeOps) {
		ArrayList<OpTpl> list = new ArrayList<OpTpl>();
		HashMap<Integer, Integer> labelMap = new HashMap<Integer, Integer>(); // label offset to index map

		for (PcodeOp pcodeOp : pcodeOps) {

			int opcode = pcodeOp.getOpcode();

			VarnodeTpl outputTpl = null;
			Varnode v = pcodeOp.getOutput();
			if (v != null) {
				outputTpl = getVarnodeTpl(addrFactory, v);
			}

			Varnode[] inputs = pcodeOp.getInputs();
			VarnodeTpl[] inputTpls = new VarnodeTpl[inputs.length];
			for (int i = 0; i < inputs.length; i++) {

				Varnode input = inputs[i];

				if (i == 0 && (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH)) {
					// Handle internal branch destination represented by constant destination
					if (input.isConstant()) {
						int labelOffset = pcodeOp.getSeqnum().getTime() + (int) input.getOffset();
						int labelIndex;
						if (labelMap.containsKey(labelOffset)) {
							labelIndex = labelMap.get(labelOffset);
						}
						else {
							labelIndex = labelMap.size();
							labelMap.put(labelOffset, labelIndex);
						}
						ConstTpl offsetTpl = new ConstTpl(ConstTpl.J_RELATIVE, labelIndex);
						ConstTpl spaceTpl = new ConstTpl(addrFactory.getConstantSpace());
						ConstTpl sizeTpl = new ConstTpl(ConstTpl.REAL, 8);
						inputTpls[i] = new VarnodeTpl(spaceTpl, offsetTpl, sizeTpl);
						continue;
					}
				}
				inputTpls[i] = getVarnodeTpl(addrFactory, input);
			}

			list.add(new OpTpl(opcode, outputTpl, inputTpls));
		}

		// Insert label templates from the bottom-up
		ArrayList<Integer> offsetList = new ArrayList<Integer>(labelMap.keySet());
		Collections.sort(offsetList);
		for (int i = offsetList.size() - 1; i >= 0; i--) {
			int labelOffset = offsetList.get(i);
			int labelIndex = labelMap.get(labelOffset);
			OpTpl labelTpl = getLabelOpTemplate(addrFactory, labelIndex);
			list.add(labelOffset, labelTpl);
		}

		return list;
	}

	/**
	 * Create label OpTpl. Uses overloaded PcodeOp.PTRADD with input[0] = labelIndex
	 * 
	 * @param addrFactory
	 * @param labelIndex
	 * @return label OpTpl
	 */
	private static OpTpl getLabelOpTemplate(AddressFactory addrFactory, int labelIndex) {
		ConstTpl offsetTpl = new ConstTpl(ConstTpl.REAL, labelIndex);
		ConstTpl spaceTpl = new ConstTpl(addrFactory.getConstantSpace());
		ConstTpl sizeTpl = new ConstTpl(ConstTpl.REAL, 8);
		VarnodeTpl input = new VarnodeTpl(spaceTpl, offsetTpl, sizeTpl);
		return new OpTpl(PcodeOp.PTRADD, null, new VarnodeTpl[] { input });
	}

	private static VarnodeTpl getVarnodeTpl(AddressFactory addrFactory, Varnode v) {
		ConstTpl offsetTpl = new ConstTpl(ConstTpl.REAL, v.getOffset());
		AddressSpace addressSpace = addrFactory.getAddressSpace(v.getSpace());
		if (addressSpace == null) {
			throw new IllegalArgumentException("Unknown varnode space ID: " + v.getSpace());
		}
		ConstTpl spaceTpl = new ConstTpl(addressSpace);
		ConstTpl sizeTpl = new ConstTpl(ConstTpl.REAL, v.getSize());
		return new VarnodeTpl(spaceTpl, offsetTpl, sizeTpl);
	}
}
