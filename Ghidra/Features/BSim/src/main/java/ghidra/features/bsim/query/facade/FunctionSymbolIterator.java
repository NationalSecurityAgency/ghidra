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
package ghidra.features.bsim.query.facade;

import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.listing.Function;

import java.util.Iterator;

/**
 *  Convert an iterator over FunctionSymbols into an iterator over the Functions
 */
public class FunctionSymbolIterator implements Iterator<Function> {

	private Iterator<FunctionSymbol> symiter;
	
	public FunctionSymbolIterator(Iterator<FunctionSymbol> iter) {
		symiter = iter;
	}
	
	@Override
	public boolean hasNext() {
		return symiter.hasNext();
	}

	@Override
	public Function next() {
		FunctionSymbol sym = symiter.next();
		if (sym == null)
			return null;
		Object obj = sym.getObject();
		if (obj==null) return null;
		return (Function)obj;
	}

	@Override
	public void remove() {
		// not functional
		
	}

}
