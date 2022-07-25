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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;

public class InjectContext {

	public SleighLanguage language;
	public Address baseAddr;		// Base address of op (call,userop) causing the inject
	public Address nextAddr;		// Address of next instruction following the injecting instruction
	public Address callAddr;		// For a call inject, the address of the function being called
	public Address refAddr;
	public ArrayList<Varnode> inputlist;	// Input parameters for the injection
	public ArrayList<Varnode> output;		// Output parameters

	public InjectContext() {
	}

	public void decode(Decoder decoder) throws PcodeXMLException {
		int el = decoder.openElement(ELEM_CONTEXT);
		baseAddr = AddressXML.decode(decoder);
		callAddr = AddressXML.decode(decoder);
		int subel = decoder.peekElement();
		if (subel == ELEM_INPUT.id()) {
			decoder.openElement();
			inputlist = new ArrayList<>();
			for (;;) {
				int addrel = decoder.peekElement();
				if (addrel == 0) {
					break;
				}
				decoder.openElement();
				Address addr = AddressXML.decodeFromAttributes(decoder);
				int size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
				decoder.closeElement(addrel);
				inputlist.add(new Varnode(addr, size));
			}
			decoder.closeElement(subel);
			subel = decoder.peekElement();
		}
		if (subel == ELEM_OUTPUT.id()) {
			decoder.openElement();
			output = new ArrayList<>();
			for (;;) {
				int addrel = decoder.peekElement();
				if (addrel == 0) {
					break;
				}
				decoder.openElement();
				Address addr = AddressXML.decodeFromAttributes(decoder);
				int size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
				decoder.closeElement(addrel);
				output.add(new Varnode(addr, size));
			}
			decoder.closeElement(subel);
		}
		decoder.closeElement(el);
	}
}
