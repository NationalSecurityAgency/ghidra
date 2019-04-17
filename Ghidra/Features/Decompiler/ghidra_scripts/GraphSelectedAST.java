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
//Decompile the function at the cursor, then build data-flow graph (AST) for the current address
//@category PCode

import java.util.Iterator;

import ghidra.program.model.pcode.PcodeOpAST;

public class GraphSelectedAST extends GraphAST {
	
	protected Iterator<PcodeOpAST> getPcodeOpIterator() {
		Iterator<PcodeOpAST> opiter = high.getPcodeOps(this.currentAddress);
		return opiter;
	}
  
}
