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
package ghidra.app.plugin.match;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;

/**
 *
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class FunctionMatchSet extends ArrayList<SubroutineMatch> {
	public final Program aProgram;
	public final Program bProgram;
	private final SymbolTable aSymbolTable;
	private final SymbolTable bSymbolTable;

	/**
	 * @param thisProgramName Name of this program (i.e. the program from
	 * which the matching was initiated.
	 * @param otherProgramName Name of the program being matched.
	 */
	public FunctionMatchSet(Program aProgram, Program bProgram) {
		super();
		this.aProgram = aProgram;
		this.bProgram = bProgram;
		this.aSymbolTable = aProgram.getSymbolTable();
		this.bSymbolTable = bProgram.getSymbolTable();

	}

	/**
	 * @return The sorted array of matches.
	 */
	public SubroutineMatch[] getMatches() {
		SubroutineMatch[] theMatches = this.toArray(new SubroutineMatch[0]);
		return theMatches;
	}

//	/**
//	 * @return The match as an Object array.
//	 */
//	public Object[] getResultsArray(SubroutineMatch m) {
//		Object[] a = new Object[7];
//		Address aAddr = m.getAAddresses()[0];
//		a[0] = aAddr;
//		a[1] = aSymbolTable.getPrimarySymbol( aAddr );
//		a[2] = new Integer( getLength( aAddr, aModel ));
//		Address bAddr = m.getBAddresses()[0];
//		a[3] = bAddr;
//		a[4] = bSymbolTable.getPrimarySymbol( bAddr );
//		a[5] = new Integer( getLength( bAddr, bModel ) );
//		a[6] = m.getReason();
//		return a;
//	}

	public int getLength(Address addr, Program aProgram) {
		Function func = aProgram.getFunctionManager().getFunctionContaining(addr);
		AddressSetView asv = func.getBody();
		return (int) asv.getNumAddresses();

	}

	/** Assumes the address is in program a */
	public int getLength(Address addr) {
		return getLength(addr, aProgram);
	}

	SymbolTable getATable() {
		return aSymbolTable;
	}

	SymbolTable getBTable() {
		return bSymbolTable;
	}

}
