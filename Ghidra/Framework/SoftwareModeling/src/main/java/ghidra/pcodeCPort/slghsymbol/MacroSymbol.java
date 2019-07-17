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

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.semantics.ConstructTpl;
import ghidra.sleigh.grammar.Location;

public class MacroSymbol extends SleighSymbol {

	private int index;
	private ConstructTpl construct;
	private VectorSTL<OperandSymbol> operands = new VectorSTL<OperandSymbol>();

	public MacroSymbol( Location location, String nm, int i ) {
		super( location, nm );
		index = i;
		construct = null;
	}

	public int getIndex() {
		return index;
	}

	public void setConstruct( ConstructTpl ct ) {
		construct = ct;
	}

	public ConstructTpl getConstruct() {
		return construct;
	}

	public void addOperand( OperandSymbol sym ) {
		operands.push_back( sym );
	}

	public int getNumOperands() {
		return operands.size();
	}

	public OperandSymbol getOperand( int i ) {
		return operands.get( i );
	}

	@Override
    public symbol_type getType() {
		return symbol_type.macro_symbol;
	}
}
