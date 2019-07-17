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
/*
 * Created on Jul 28, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.plugin.processors.generic;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.NotYetImplementedException;

import java.util.ArrayList;

/**
 * 
 *
 * Template for a constructor which is officially "unimplemented" as opposed to a
 * constructor which does nothing (like a NOP). Any instruction which is "unimplemented"
 * in this way will have its disassembly printed correctly but will be treated as an
 * instruction which does nothing (and falls through) for any analysis that needs
 * control-flow information or semantics. Actually anything that tries to get semantic
 * information (via the getPcode call) will cause an exception to be thrown, as opposed
 * to a NOP instruction which would return an empty pcode op array. The caller can then
 * catch the exception and treat the instruction as special, or it can ignore the exception
 * in which case the instruction behaves exactly like a NOP.
 */
public class UnimplementedConstructor extends ConstructorPcodeTemplate {
	public UnimplementedConstructor() {
		super();
		try {
			optimize();					// Set the default flowtype
		}
		catch(Exception e) {}
	 }
	@Override
    public void addPcodeOpTemplate(Object opT) throws SledException { 
		// Since this is unimplemented we ignore any ops assigned to it
	}
	@Override
    public Handle getPcode(ArrayList<PcodeOp> pcode, Position position, int off, ArrayList<PcodeOp> delayPcode) throws NotYetImplementedException {
		throw new NotYetImplementedException("Constructor is unimplemented");
	}
}
