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
package ghidra.program.model.listing;

import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

public enum FlowOverride {

	// New instances may be appended but not inserted in the list below!!

	/**
	 * No flow override has been established
	 */
	NONE,

	/**
	 * Override the primary CALL or RETURN with a suitable JUMP operation.
	 * <pre>{@literal
	 *   Pcode mapping:
	 *      CALL -> BRANCH
	 *      RETURN -> BRANCHIND
	 * }</pre>
	 */
	BRANCH,

	/**
	 * Override the primary BRANCH or RETURN with a suitable CALL operation.
	 * <pre>{@literal
	 * 	 Pcode mapping:
	 * 		BRANCH -> CALL
	 *      BRANCHIND -> CALLIND
	 *      CBRANCH <addr>,<cond> -> (complex mapping)
	 *          tmp = BOOL_NEGATE <cond>
	 *      	CBRANCH <label>,tmp
	 *          CALL <addr>
	 *        <label>
	 *      RETURN -> CALLIND
	 * }</pre>
	 */
	CALL,

	/**
	 * Override the primary BRANCH or RETURN with a suitable CALL/RETURN operation.
	 * <pre>{@literal
	 * 	 Pcode mapping:
	 * 		BRANCH -> CALL/RETURN
	 *      BRANCHIND -> CALLIND/RETURN
	 *      CBRANCH <addr>,<cond> -> (complex mapping)
	 *          tmp = BOOL_NEGATE <cond>
	 *      	CBRANCH <label>,tmp
	 *          CALL <addr>
	 *          RETURN 0
	 *        <label>
	 *      RETURN -> CALLIND/RETURN
	 * }</pre>
	 */
	CALL_RETURN,

	/**
	 * Override the primary BRANCH or CALL with a suitable RETURN operation.
	 * <pre>{@literal
	 *   Pcode mapping:
	 *      BRANCH <addr>  -> (complex mapping)
	 *          tmp = COPY &<addr>
	 *          RETURN tmp
	 *      BRANCHIND -> RETURN
	 *      CBRANCH <addr>,<cond>  -> (complex mapping)
	 *      	tmp = BOOL_NEGATE <cond>
	 *      	CBRANCH <label>,tmp
	 *          tmp2 = COPY &<addr>
	 *          RETURN tmp2
	 *        <label>
	 *      CALL <addr>    -> (complex mapping)
	 *          tmp = COPY &<addr>
	 *          RETURN tmp
	 *      CALLIND -> RETURN
	 * }</pre>
	 */
	RETURN;

	/**
	 * Return FlowOrdinal with the specified ordinal value.
	 * NONE will be returned for an unknown value.
	 * @param ordinal
	 * @return FlowOrdinal
	 */
	public static FlowOverride getFlowOverride(int ordinal) {
		for (FlowOverride value : FlowOverride.values()) {
			if (value.ordinal() == ordinal) {
				return value;
			}
		}
		return NONE;
	}

	/**
	 * Get modified FlowType resulting from the application of the specified flowOverride
	 * @param originalFlowType
	 * @param flowOverride
	 * @return modified flow type
	 */
	public static FlowType getModifiedFlowType(FlowType originalFlowType,
			FlowOverride flowOverride) {
		FlowType flowType = originalFlowType;
		if (flowOverride == FlowOverride.NONE ||
			!flowType.isJump() && !flowType.isTerminal() && !flowType.isCall()) {
			return flowType;
		}
		// NOTE: The following flow-type overrides assume that a return will always 
		// be the last flow pcode-op - since it is the first primary flow pcode-op
		// that will get replaced.
		if (flowOverride == FlowOverride.BRANCH) {
			if (flowType.isJump()) {
				return flowType;
			}
			if (flowType.isConditional()) {
				// assume that we will never start with a complex flow with terminator
				// i.e., CONDITIONAL-JUMP-TERMINATOR
				if (flowType.isTerminal()) {
					// assume return replaced
					return RefType.CONDITIONAL_COMPUTED_JUMP;
				}
				return RefType.CONDITIONAL_JUMP;
			}
			if (flowType.isComputed()) {
				return RefType.COMPUTED_JUMP;
			}
			if (flowType.isTerminal()) {
				// assume return replaced
				return RefType.COMPUTED_JUMP;
			}
			return RefType.UNCONDITIONAL_JUMP;
		}
		else if (flowOverride == FlowOverride.CALL) {
			if (flowType.isCall()) {
				return flowType;
			}
			if (flowType.isConditional()) {
				if (flowType.isTerminal() && (flowType.isCall() || flowType.isJump())) {
					// assume original return was preserved
					return RefType.CONDITIONAL_CALL_TERMINATOR;
				}
				if (flowType.isTerminal()) {
					// assume return was replaced
					return RefType.CONDITIONAL_COMPUTED_CALL;
				}
				return RefType.CONDITIONAL_CALL;
			}
			if (flowType.isComputed()) {
				if (flowType.isTerminal() && (flowType.isCall() || flowType.isJump())) {
					// assume original return was preserved
					return RefType.COMPUTED_CALL_TERMINATOR;
				}
				return RefType.COMPUTED_CALL;
			}
			if (flowType.isTerminal() && (flowType.isCall() || flowType.isJump())) {
				// assume original return was preserved
				return RefType.CALL_TERMINATOR;
			}
			if (flowType.isTerminal()) {
				// assume return was replaced
				return RefType.COMPUTED_CALL;
			}
			return RefType.UNCONDITIONAL_CALL;
		}
		else if (flowOverride == FlowOverride.CALL_RETURN) {
			if (flowType.isConditional()) {
				if (flowType.isComputed()) {
					return RefType.CONDITIONAL_COMPUTED_CALL;
				}
				if (flowType.isTerminal()) {
					// assume return was replaced
					return RefType.COMPUTED_CALL_TERMINATOR;
				}
				return flowType;  // don't replace
			}
			if (flowType.isComputed()) {
				return RefType.COMPUTED_CALL_TERMINATOR;
			}
			if (flowType.isTerminal()) {
				// assume return was replaced
				return RefType.COMPUTED_CALL_TERMINATOR;
			}
			return RefType.CALL_TERMINATOR;
		}
		else if (flowOverride == FlowOverride.RETURN) {
			if (flowType.isConditional()) {
				return RefType.CONDITIONAL_TERMINATOR;
			}
			return RefType.TERMINATOR;
		}
		return flowType;
	}

}
