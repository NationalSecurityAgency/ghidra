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
package ghidra.app.decompiler.signature;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;

/**
 * An unordered list of features describing a single function.
 * Each feature represents partial information about the control-flow and/or data-flow
 * making up the function. Together the features form an (approximately) complete representation
 * of the function. Each feature is represented internally as 32-bit hash.  Details of how the
 * feature was formed are not available through this object, but see {@link DebugSignature}
 * This object may optionally include a list of addresses of functions directly called by
 * the function being described. 
 */
public class SignatureResult {
	public int[] features;				// Raw features of the result
	public ArrayList<Address> calllist;	// List of addresses being called
	public boolean hasunimplemented;	// Function has unimplemented instructions
	public boolean hasbaddata;			// Instruction flow went into baddata

	/**
	 * Decode a sequence of raw feature hashes associated with a specific function from a stream.
	 * The stream may optionally include addresses of called functions.
	 * @param decoder is the stream decoder
	 * @param func is the specific function being described
	 * @param keepcalllist is true if call addresses should be stored in the result object
	 * @return the decoded SignatureResult
	 * @throws DecoderException for problems reading from the stream
	 */
	public static SignatureResult decode(Decoder decoder, Function func, boolean keepcalllist)
			throws DecoderException {
		ArrayList<Integer> res = null;
		ArrayList<Address> calllist = null;
		boolean hasunimpl = false;
		boolean hasbaddata = false;
		if (keepcalllist) {
			calllist = new ArrayList<>();
		}
		int start = decoder.openElement(ELEM_SIGNATURES);
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_UNIMPL.id()) {
				hasunimpl = decoder.readBool();
			}
			else if (attribId == ATTRIB_BADDATA.id()) {
				hasbaddata = decoder.readBool();
			}
		}
		res = new ArrayList<>();
		for (;;) {
			int subel = decoder.openElement();
			if (subel == 0) {
				break;
			}
			if (subel == ELEM_SIG.id()) {
				int val = (int) decoder.readUnsignedInteger(ATTRIB_VAL);
				res.add(val);
			}
			else {
				Address addr = AddressXML.decodeFromAttributes(decoder);
				if (keepcalllist) {
					calllist.add(addr);
				}
			}
			decoder.closeElement(subel);
		}
		decoder.closeElement(start);

		SignatureResult sigres = new SignatureResult();
		sigres.calllist = calllist;
		sigres.hasunimplemented = hasunimpl;
		sigres.hasbaddata = hasbaddata;
		sigres.features = new int[res.size()];
		for (int i = 0; i < res.size(); ++i) {
			sigres.features[i] = res.get(i).intValue();
		}
		return sigres;
	}

}
