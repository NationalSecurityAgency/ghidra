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
//Resolves relative references computed off EBX. 
//This will resolve references to strings in the "__cstring" section.
//@category Mac OS X

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Conv;

public class ResolveReferencesRelativeToEbxScript extends GhidraScript {

	private Register EBX;

	@Override
	public void run() throws Exception {

		EBX = currentProgram.getLanguage().getRegister("EBX");

		FunctionIterator functions = currentProgram.getListing().getFunctions(true);

		while ( functions.hasNext() ) {

			if ( monitor.isCancelled() ) {
				break;
			}

			Function function = functions.next();

			monitor.setMessage( function.getName() );

			loopOverInstructionsInFunction( function );

			function = getFunctionAfter( function );
		}
	}

	private void loopOverInstructionsInFunction(Function function) {
		// find all CALL instructions

		long ebx = -1;

		InstructionIterator instructions = currentProgram.getListing().getInstructions( function.getBody(), true ) ;

		while ( instructions.hasNext() ) {

			Instruction instruction = instructions.next();

			if ( monitor.isCancelled() ) {
				break;
			}

			if ( ebx == -1 ) {
				ebx = getValueForEBX( instruction );
			}

			if ( ebx == -1 ) {
				continue;
			}

			for (int i = 0 ; i < instruction.getNumOperands() ; ++i ) {

				Object [] opObjects = instruction.getOpObjects(i);

				if ( opObjects.length == 2 ) {

					if (opObjects[ 0 ] instanceof Scalar && opObjects[ 1 ] instanceof Register ) {

 						Scalar scalar = (Scalar) opObjects[ 0 ];

						Register register = (Register) opObjects[ 1 ];

						if ( register.equals( EBX ) ) {

							Address address = toAddr( (ebx + scalar.getUnsignedValue()) & Conv.INT_MASK );

							if ( isValid( address ) ) {

								removeReferencesFrom(instruction);

								Reference reference = createMemoryReference( instruction, 1, address, RefType.DATA );

								setReferencePrimary( reference );

								println( "Creating reference from " + instruction.getMinAddress() + " to " + address );
							}
						}
					}
				}
			}
		}
	}

	private boolean isValid(Address address) {

		Instruction instruction = getInstructionContaining( address );
		if ( instruction != null ) {
			Address min = instruction.getMinAddress();
			if ( address.compareTo( min ) > 0 ) {
				return false; //off-cut
			}
		}

		Data data = getDataContaining( address );
		if ( data != null ) {
			Address min = data.getMinAddress();
			if ( address.compareTo( min ) > 0 ) {
				return false; //off-cut
			}
		}

		return currentProgram.getMemory().contains( address );
	}

	private void removeReferencesFrom(Instruction instruction) {
		Reference [] referencesFrom = instruction.getReferencesFrom();
		for (Reference reference : referencesFrom) {
			removeReference( reference );
		}
	}

	private long getValueForEBX(Instruction instruction) {

		if ( instruction.getMnemonicString().equals( "CALL" ) ) {

			Address nextInstructionAddress = instruction.getMaxAddress().add( 1 );

			Reference [] referencesFrom = instruction.getReferencesFrom();

			if ( referencesFrom.length == 1) {

				if ( referencesFrom[0].getToAddress().equals( nextInstructionAddress ) ) {

					return nextInstructionAddress.getOffset();
				}
			}
		}
		return -1;
	}

}
