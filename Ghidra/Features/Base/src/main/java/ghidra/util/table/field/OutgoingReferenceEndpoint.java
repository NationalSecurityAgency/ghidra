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
package ghidra.util.table.field;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;

/**
 * Marker row object that signals to the table API that the references contained therein all
 * share the <code>from</code> address, with each row showing the <code>to</code> address.
 */
public class OutgoingReferenceEndpoint extends ReferenceEndpoint {

	public OutgoingReferenceEndpoint(Reference r, boolean isOffcut) {
		super(r, r.getToAddress(), r.getReferenceType(), isOffcut, r.getSource());
	}

	/**
	 * A special constructor that allows clients to override the 'toAddress' of the reference.
	 * 
	 * @param r the reference 
	 * @param toAddress the desired 'toAddress'
	 * @param isOffcut false if the given reference points to the min address of a code unit
	 */
	public OutgoingReferenceEndpoint(Reference r, Address toAddress, boolean isOffcut) {
		super(r, toAddress, r.getReferenceType(), isOffcut, r.getSource());
	}

	@Override
	public String toString() {
		return "Outgoing " + getReferenceType().getName();
	}
}
