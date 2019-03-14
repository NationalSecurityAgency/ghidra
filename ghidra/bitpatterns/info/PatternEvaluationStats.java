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
package ghidra.bitpatterns.info;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to store a List of {@link PatternEvalRowObjects} and to accumulate
 * stats of whether or not addresses where patterns match truly are function starts.
 */
public class PatternEvaluationStats {

	private int truePositives;
	private int possible_start_code;
	private int fp_wrong_flow;
	private int fp_misaligned;
	private int fp_data;
	private int inUndefined;
	private int contextConflicts;
	private int pre_pattern_hit;

	private List<PatternEvalRowObject> rowObjects;

	/**
	 * Create a new {@link PatternEvaluationStats} object with all counters initialized to 0.
	 */
	public PatternEvaluationStats() {
		truePositives = 0;
		possible_start_code = 0;
		fp_wrong_flow = 0;
		fp_misaligned = 0;
		fp_data = 0;
		inUndefined = 0;
		contextConflicts = 0;
		pre_pattern_hit = 0;
		rowObjects = new ArrayList<>();
	}

	/**
	 * Get the number of matches which are true positives
	 * @return number of true positives
	 */
	public int getNumTruePositives() {
		return truePositives;
	}

	private void incTruePositives() {
		truePositives++;
	}

	/**
	 * Get the number of matches which are possible functions starts in defined code
	 * @return number of possible starts in code
	 */
	public int getNumPossibleStartCode() {
		return possible_start_code;
	}

	private void incNumPossibleStartCode() {
		possible_start_code++;
	}

	/**
	 * Get the number of matches which are false positives since they have the wrong incoming flow to
	 * be a function start
	 * @return number of false positives due to incorrect flow
	 */
	public int getNumWrongFlow() {
		return fp_wrong_flow;
	}

	private void incNumFPWithinBlock() {
		fp_wrong_flow++;
	}

	/**
	 * Get the number of matches which are false positives since they occur within a defined instruction
	 * @return number of matches within instructions
	 */
	public int getNumFPMisaligned() {
		return fp_misaligned;
	}

	private void incNumFPMisaligned() {
		fp_misaligned++;
	}

	/**
	 * Get the number of matches which are false positives since they occur in defined data
	 * @return number of matches within data
	 */
	public int getNumFPData() {
		return fp_data;
	}

	private void incNumFPData() {
		fp_data++;
	}

	/**
	 * Get the number of matches which occur within undefined bytes
	 * @return number of matches within undefined bytes
	 */
	public int getNumUndefined() {
		return inUndefined;
	}

	private void incNumUndefined() {
		inUndefined++;
	}

	private void incNumContextConflicts() {
		contextConflicts++;
	}

	/**
	 * Get the number of matches which are false positives due to context register conflicts
	 * @return number of matches which are context register conflicts
	 */
	public int getNumContextConflicts() {
		return contextConflicts++;
	}

	/**
	 * Returns the {@code PatternEvalRowObject}s
	 * @return the {@code PatternEvalRowObject}s
	 */
	public List<PatternEvalRowObject> getRowObjects() {
		return rowObjects;
	}

	/**
	 * Add a {@code PatternEvalRowObject} and update the stats appropriately
	 * @param rowObject the {@link PatternEvalRowObject} to add
	 */
	public void addRowObject(PatternEvalRowObject rowObject) {
		rowObjects.add(rowObject);
		switch (rowObject.getMatchType()) {
			case TRUE_POSITIVE:
				incTruePositives();
				break;
			case POSSIBLE_START_CODE:
				incNumPossibleStartCode();
				break;
			case FP_WRONG_FLOW:
				incNumFPWithinBlock();
				break;
			case FP_MISALIGNED:
				incNumFPMisaligned();
				break;
			case FP_DATA:
				incNumFPData();
				break;
			case POSSIBLE_START_UNDEFINED:
				incNumUndefined();
				break;
			case CONTEXT_CONFLICT:
				incNumContextConflicts();
				break;
			case PRE_PATTERN_HIT:
				incNumPrePatternHit();
			default:
				break;
		}
	}

	private void incNumPrePatternHit() {
		pre_pattern_hit++;

	}

	/**
	 * Returns the number of pre-pattern hits when only pre-patterns are being evaluated
	 * @return number of pre-pattern hits
	 */
	public int getNumPrePatternHit() {
		return pre_pattern_hit;
	}

}
