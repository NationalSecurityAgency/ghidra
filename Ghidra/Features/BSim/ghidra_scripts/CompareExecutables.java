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
// Calculate similarity/signifigance scores between executables by
// combining their function scores.
//@category BSim

import java.net.URL;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.client.*;
import ghidra.features.bsim.query.description.ExecutableRecord;

public class CompareExecutables extends GhidraScript {

	private ExecutableComparison exeCompare;
	@Override
	protected void run() throws Exception {
		URL url = BSimClientFactory.deriveBSimURL("ghidra://localhost/repo");
		try (FunctionDatabase database = BSimClientFactory.buildClient(url, true)) {
			//		FileScoreCaching cache = new FileScoreCaching("/tmp/test_scorecacher.txt");
			TableScoreCaching cache = new TableScoreCaching(database);
			exeCompare =
				new ExecutableComparison(database, 1000000, "11111111111111111111111111111111",
					cache,
					monitor);
			// Specify the list of executables to compare by giving their md5 hash
			//		exeCompare.addExecutable("22222222222222222222222222222222");	// 32 hex-digit string
			//		exeCompare.addExecutable("33333333333333333333333333333333");
			exeCompare.addAllExecutables(5000);
			ExecutableScorer scorer = exeCompare.getScorer();
			if (!exeCompare.isConfigured()) {
				exeCompare.resetThresholds(0.7, 10.0);
			}
			exeCompare.fillinSelfScores();	// Prefetch self-scores, calculate any we are missing

			exeCompare.performScoring();
			scorer.commitSelfScore();		// Commit the newly calculated self-score

			println("Maximum cluster size = " + Integer.toString(exeCompare.getMaxHitCount()));
			println("Hit count exceeded = " + Integer.toString(exeCompare.getExceedCount()));
			float scoreThresh = 0.01f;
			int numExe = scorer.numExecutables();
			ExecutableRecord exeA = scorer.getSingularExecutable();
			float selfScoreA = scorer.getSingularSelfScore();
			for (int i = 1; i <= numExe; ++i) {
				ExecutableRecord exeB = scorer.getExecutable(i);
				float selfScoreB = scorer.getScore(i);
				if (selfScoreB == 0.0f) {	// This is possible if the executable has no "rare" functions.
					continue;				//   as defined by the ExecutableComparison.hitCountThreshold
				}
				ExecutableRecord smallRecord = selfScoreA < selfScoreB ? exeA : exeB;
				ExecutableRecord bigRecord = selfScoreA < selfScoreB ? exeB : exeA;
				float libScore = scorer.getNormalizedScore(i, true);
				float totalScore = scorer.getNormalizedScore(i, false);
				if (libScore < scoreThresh) {
					continue;
				}
				println(smallRecord.getNameExec() + " " + bigRecord.getNameExec());
				println("  " + Float.toString(libScore) + " library score");
				println("  " + Float.toString(totalScore) + " total score");
			}
		}
	}

}
