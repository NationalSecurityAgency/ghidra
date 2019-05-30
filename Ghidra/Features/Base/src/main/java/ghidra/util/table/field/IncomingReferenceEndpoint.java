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

import ghidra.program.model.symbol.Reference;

/**
 * Marker row object that signals to the table API that the references contained therein all
 * share the <code>to</code> address, with each row showing the <code>from</code> address.
 */
public class IncomingReferenceEndpoint extends ReferenceEndpoint {

	public IncomingReferenceEndpoint(Reference r, boolean isOffcut) {
		super(r, r.getFromAddress(), r.getReferenceType(), isOffcut, r.getSource());
	}

	@Override
	public String toString() {
		return "Incoming " + getReferenceType().getName();
	}
}
