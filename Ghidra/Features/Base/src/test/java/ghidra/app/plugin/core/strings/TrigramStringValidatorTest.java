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
package ghidra.app.plugin.core.strings;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.junit.Before;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.string.NGramUtils;
import ghidra.app.plugin.core.string.StringAndScores;
import ghidra.app.services.StringValidatorQuery;
import ghidra.app.services.StringValidityScore;
import ghidra.framework.Application;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import utilities.util.FileUtilities;

public class TrigramStringValidatorTest extends AbstractGhidraHeadlessIntegrationTest {

	TrigramStringValidator ngramValidator;

	@Before
	public void setup() throws IOException {
		ResourceFile stringModelFile =
			Application.findDataFileInAnyModule("stringngrams/StringModel.sng");
		NGramUtils.startNewSession("StringModel.sng", true);
		ngramValidator = TrigramStringValidator.read(stringModelFile);
	}

	private void assertSameStringScore(String s) {
		StringValidityScore score =
			ngramValidator.getStringValidityScore(new StringValidatorQuery(s));

		StringAndScores sas = new StringAndScores(s, true);
		NGramUtils.scoreString(sas);

		assertEquals(sas.getScoreThreshold(), score.threshold(), 0.0);
		assertEquals(sas.isScoreAboveThreshold(), score.isScoreAboveThreshold());
	}

	//@Test
	public void testCompareOldAndNewScoring() throws IOException {
		List<String> lines = FileUtilities.getLines(new File("lotsofstrings.txt"));
		for (String s : lines) {
			assertSameStringScore(s);
		}
	}
}
