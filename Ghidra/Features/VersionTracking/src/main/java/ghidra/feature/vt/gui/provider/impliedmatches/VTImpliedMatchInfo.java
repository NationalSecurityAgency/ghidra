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
package ghidra.feature.vt.gui.provider.impliedmatches;

import ghidra.feature.vt.api.main.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * A {@link VTMatchInfo} object that represents the concept of an implied match.  This type
 * of match exists because two functions share references to the same data or functions.
 */
public class VTImpliedMatchInfo extends VTMatchInfo {
	private Reference sourceReference;
	private Reference destinationReference;

	public VTImpliedMatchInfo(VTMatchSet matchSet, Reference sourceRef, Reference destinationRef) {
		super(matchSet);

		this.sourceReference = sourceRef;
		this.destinationReference = destinationRef;
	}

	public Reference getSourceReference() {
		return sourceReference;
	}

	public Reference getDestinationReference() {
		return destinationReference;
	}

	public Address getSourceReferenceAddress() {
		return sourceReference.getFromAddress();
	}

	public Address getDestinationReferenceAddress() {
		return destinationReference.getFromAddress();
	}

	public ProgramLocation getSourceReferenceLocation() {
		VTSession session = matchSet.getSession();
		Program program = session.getSourceProgram();
		return new OperandFieldLocation(program, sourceReference.getFromAddress(), null, sourceReference.getToAddress(),
			"", sourceReference.getOperandIndex(), 0);
	}

	public ProgramLocation getDestinationReferenceLocation() {
		VTSession session = matchSet.getSession();
		Program program = session.getDestinationProgram();
		return new OperandFieldLocation(program, destinationReference.getFromAddress(), null, destinationReference.getToAddress(),
			"", destinationReference.getOperandIndex(), 0);
	}
}
