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
 * Created on Nov 10, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package ghidra.app.plugin.match;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;

/**
 *
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class SubroutineMatchSet extends ArrayList<SubroutineMatch> {
	public final Program aProgram;
	public final Program bProgram;
	private final SymbolTable aSymbolTable;
	private final SymbolTable bSymbolTable;
	private final CodeBlockModel aModel;
	private final CodeBlockModel bModel;

	/**
	 * @param thisProgramName Name of this program (i.e. the program from
	 * which the matching was initiated.
	 * @param otherProgramName Name of the program being matched.
	 */
	public SubroutineMatchSet(Program aProgram, CodeBlockModel aModel, Program bProgram,
			CodeBlockModel bModel) {
		super();
		this.aProgram = aProgram;
		this.bProgram = bProgram;
		this.aSymbolTable = aProgram.getSymbolTable();
		this.bSymbolTable = bProgram.getSymbolTable();
		this.aModel = aModel;
		this.bModel = bModel;
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

	public int getLength(Address addr, CodeBlockModel model) {
		int length = 0;
		try {
			CodeBlock block = model.getCodeBlockAt(addr, null);
			length = (int) block.getNumAddresses();
		}
		catch (Exception e) {
			return 0;
		}
		return length;

	}

	/** Assumes the address is in program a */
	public int getLength(Address addr) {
		return getLength(addr, aModel);
	}

	CodeBlockModel getAModel() {
		return aModel;
	}

	CodeBlockModel getBModel() {
		return bModel;
	}

	SymbolTable getATable() {
		return aSymbolTable;
	}

	SymbolTable getBTable() {
		return bSymbolTable;
	}

}
