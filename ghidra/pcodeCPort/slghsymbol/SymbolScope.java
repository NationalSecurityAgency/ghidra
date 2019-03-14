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

import generic.stl.IteratorSTL;
import generic.stl.Pair;

public class SymbolScope {

	SymbolScope parent;
	SymbolTree tree = new SymbolTree();
	int id;

	public SymbolScope( SymbolScope p, int i ) {
		parent = p;
		id = i;
	}

	public SymbolScope getParent() {
		return parent;
	}

	public IteratorSTL<SleighSymbol> begin() {
		return tree.begin();
	}

	public IteratorSTL<SleighSymbol> end() {
		return tree.end();
	}

	public int getId() {
		return id;
	}

	public void removeSymbol( SleighSymbol a ) {
		tree.erase( a );
	}

	public SleighSymbol addSymbol( SleighSymbol a ) {

		Pair<IteratorSTL<SleighSymbol>, Boolean> res = tree.insert( a );
		if ( !res.second ) {
			return res.first.get(); // Symbol already exists in this table
		}
		return a;
	}

	public SleighSymbol findSymbol( String nm ) {
		SleighSymbol dummy = new SleighSymbol( null, nm );
		IteratorSTL<SleighSymbol> iter = tree.find( dummy );
		if ( !iter.isEnd() ) {
			return iter.get();
		}
		return null;
	}

	public void dispose() {
	}

	@Override
    public String toString() {
	    StringBuilder sb = new StringBuilder();
	    sb.append("[ ");
	    sb.append(id);
	    sb.append(": ");
	    sb.append(tree);
	    sb.append(" ]");
	    return sb.toString();
	}
}
