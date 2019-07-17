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

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class PatternEvalutationStatsTest extends AbstractGenericTest {

	@Test
	public void basicTest() {
		PatternEvaluationStats patternStats = new PatternEvaluationStats();
		PatternEvalRowObject row =
			new PatternEvalRowObject(PatternMatchType.TRUE_POSITIVE, null, null, null, 0, 0);
		patternStats.addRowObject(row);
		row = new PatternEvalRowObject(PatternMatchType.CONTEXT_CONFLICT, null, null, null, 0, 0);
		patternStats.addRowObject(row);
		row = new PatternEvalRowObject(PatternMatchType.FP_DATA, null, null, null, 0, 0);
		patternStats.addRowObject(row);
		row = new PatternEvalRowObject(PatternMatchType.FP_MISALIGNED, null, null, null, 0, 0);
		patternStats.addRowObject(row);
		row = new PatternEvalRowObject(PatternMatchType.FP_WRONG_FLOW, null, null, null, 0, 0);
		patternStats.addRowObject(row);
		row =
			new PatternEvalRowObject(PatternMatchType.POSSIBLE_START_CODE, null, null, null, 0, 0);
		patternStats.addRowObject(row);
		row = new PatternEvalRowObject(PatternMatchType.POSSIBLE_START_UNDEFINED, null, null, null,
			0, 0);
		patternStats.addRowObject(row);
		row = new PatternEvalRowObject(PatternMatchType.PRE_PATTERN_HIT, null, null, null, 0, 0);
		patternStats.addRowObject(row);

		assertEquals(1, patternStats.getNumContextConflicts());
		assertEquals(1, patternStats.getNumFPData());
		assertEquals(1, patternStats.getNumFPMisaligned());
		assertEquals(1, patternStats.getNumPossibleStartCode());
		assertEquals(1, patternStats.getNumPrePatternHit());
		assertEquals(1, patternStats.getNumTruePositives());
		assertEquals(1, patternStats.getNumUndefined());
		assertEquals(1, patternStats.getNumWrongFlow());
	}
}
