/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.sleigh.grammar.Location;

public class LabelSymbol extends SleighSymbol {

	private int index; // Local 1 up index of label
	private boolean isplaced; // Has the label been placed (not just referenced)
	private int refcount; // Number of references to this label

	public LabelSymbol( Location location, String nm, int i ) {
		super( location, nm );
		index = i;
		refcount = 0;
		isplaced = false;
	}

	public int getIndex() {
		return index;
	}

	public void incrementRefCount() {
		refcount += 1;
	}

	public int getRefCount() {
		return refcount;
	}

	public void setPlaced() {
		isplaced = true;
	}

	public boolean isPlaced() {
		return isplaced;
	}

	@Override
    public symbol_type getType() {
		return symbol_type.label_symbol;
	}

}
