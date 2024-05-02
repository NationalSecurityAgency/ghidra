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
/*
 * Created on Feb 4, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.template;

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.ArrayList;

import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * A constructor template, representing the semantic action of a SLEIGH constructor, without
 * its final context.  The constructor template is made up of a list of p-code op templates,
 * which are in turn made up of varnode templates.
 * This is one step removed from the final array of PcodeOp objects, but:
 *   - Constants may still need to incorporate context dependent address resolution and relative offsets.
 *   - Certain p-code operations may still need expansion to include a dynamic LOAD or STORE operation.
 *   - The list may hold "build" directives for sub-constructor templates.
 *   - The list may still hold "label" information for the final resolution of relative jump offsets.
 * 
 * The final PcodeOps are produced by handing this to the build() method of PcodeEmit which has
 * the InstructionContext necessary for final resolution.
 */
public class ConstructTpl {

	private int numlabels = 0;			// Number of relative-offset labels in this template
	private OpTpl[] vec;				// The semantic action of constructor
	private HandleTpl result;			// The final semantic value

	/**
	 * Constructor for use with decode
	 */
	public ConstructTpl() {
	}

	/**
	 * Manually build a constructor template. This is useful for building constructor templates
	 * outside of the normal SLEIGH pipeline, as for an internally created InjectPayload.
	 * @param opvec is the list of p-code op templates making up the constructor
	 */
	public ConstructTpl(OpTpl[] opvec) {
		vec = opvec;
		result = null;
	}

	/**
	 * Manually build a constructor template from pieces.  This is used to translate from the
	 * internal SLEIGH compiler pcodeCPort.semantics.ConstructTpl
	 * @param opvec is the list of p-code op templates making up the constructor
	 * @param res is the result handle template for the constructor
	 * @param nmLabels is the number of labels int the template
	 */
	public ConstructTpl(OpTpl[] opvec, HandleTpl res, int nmLabels) {
		vec = opvec;
		result = res;
		numlabels = nmLabels;
	}

	/**
	 * @return the number of labels needing resolution in this template
	 */
	public int getNumLabels() {
		return numlabels;
	}

	/**
	 * @return the list of p-code op templates making up this constructor template
	 */
	public OpTpl[] getOpVec() {
		return vec;
	}

	/**
	 * @return the (possibly dynamic) location of the final semantic value produced by this constructor
	 */
	public HandleTpl getResult() {
		return result;
	}

	/**
	 * Decode this template from a \<construct_tpl> tag in the stream.
	 * @param decoder is the stream
	 * @return the constructor section id described by the tag
	 * @throws DecoderException for errors in the encoding
	 */
	public int decode(Decoder decoder) throws DecoderException {
		int sectionid = -1;
		numlabels = 0;
		int el = decoder.openElement(ELEM_CONSTRUCT_TPL);
		int attrib = decoder.getNextAttributeId();
		while (attrib != 0) {
			if (attrib == ATTRIB_LABELS.id()) {
				numlabels = (int) decoder.readSignedInteger();
			}
			else if (attrib == ATTRIB_SECTION.id()) {
				sectionid = (int) decoder.readSignedInteger();
			}
			attrib = decoder.getNextAttributeId();
		}
		int handel = decoder.peekElement();
		if (handel == ELEM_NULL.id()) {
			decoder.openElement();
			decoder.closeElement(handel);
			result = null;
		}
		else {
			result = new HandleTpl();
			result.decode(decoder);
		}
		ArrayList<Object> oplist = new ArrayList<>();
		while (decoder.peekElement() != 0) {
			OpTpl op = new OpTpl();
			op.decode(decoder);
			oplist.add(op);
		}
		vec = new OpTpl[oplist.size()];
		oplist.toArray(vec);
		decoder.closeElement(el);
		return sectionid;
	}

}
