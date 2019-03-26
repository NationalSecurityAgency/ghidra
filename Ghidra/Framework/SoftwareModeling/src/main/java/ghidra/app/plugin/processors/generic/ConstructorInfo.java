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
 * Created on Apr 7, 2004
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.plugin.processors.generic;

import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
/**
 * 
 *
 * Structure for collecting cached information about an instruction
 */
public class ConstructorInfo {
	private int length;						// length of the constructor
	private int flowFlags;					// flags indicating the type of branching within this constructor
	public final static int RETURN=1;
	public final static int CALL_INDIRECT=2;
	public final static int BRANCH_INDIRECT=4;
	public final static int CALL=8;
	public final static int JUMPOUT=16;
	public final static int NO_FALLTHRU=32;		// Flow cannot come out bottom of constructor
	public final static int BRANCH_TO_END=64;
	
	public ConstructorInfo(int ln,int fl) { length = ln; flowFlags = fl; }
	public int getFlowFlags() { return flowFlags; }
	public int getLength() { return length; }
	public void addLength(int l) { length += l; }

	FlowType getFlowType() {
		switch (flowFlags) {					// Convert flags to a standard flowtype
			case 0:
			case BRANCH_TO_END:
				return RefType.FALL_THROUGH;
			case CALL:
				return RefType.UNCONDITIONAL_CALL;
			case CALL | BRANCH_TO_END:
				return RefType.CONDITIONAL_CALL;			// This could be wrong but doesn't matter much
			case CALL_INDIRECT:
				return RefType.COMPUTED_CALL;
			case CALL_INDIRECT | BRANCH_TO_END:			// This could be COMPUTED_CONDITIONAL?
				return RefType.COMPUTED_CALL;
			case BRANCH_INDIRECT | NO_FALLTHRU:
				return RefType.COMPUTED_JUMP;
			case BRANCH_INDIRECT | NO_FALLTHRU | BRANCH_TO_END:
				// This should be COMPUTED_CONDITONAL_JUMP but this doesn't exist
				// so we make it a fall thru so the disassembler can continue the flow
				return RefType.FALL_THROUGH;
			case RETURN | NO_FALLTHRU:
				return RefType.TERMINATOR;
			case RETURN | NO_FALLTHRU | BRANCH_TO_END:
				return RefType.CONDITIONAL_TERMINATOR;
			case JUMPOUT:
				return RefType.CONDITIONAL_JUMP;
			case JUMPOUT | NO_FALLTHRU:
				return RefType.UNCONDITIONAL_JUMP;
			case JUMPOUT | NO_FALLTHRU | BRANCH_TO_END:
				return RefType.CONDITIONAL_JUMP;
			case NO_FALLTHRU:
				return RefType.TERMINATOR;
			case BRANCH_TO_END | JUMPOUT:
				return RefType.CONDITIONAL_JUMP;
			case NO_FALLTHRU | BRANCH_TO_END:
				return RefType.FALL_THROUGH;
			default:
				break;
		}
		return RefType.INVALID;
	}
	 
}
