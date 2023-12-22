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
// Calculate similarity/significance scores between executables by
// combining their function scores.
//@category BSim

import java.io.IOException;
import java.net.URL;
import java.security.InvalidParameterException;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.client.*;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.protocol.QueryExeInfo;
import ghidra.features.bsim.query.protocol.ResponseExe;

/**
 * An example script using {@link ExecutableComparison} to compare executables within a BSim database.
 * The user provides the URL of the database and the name of an executable within the database that
 * will be compared against every other executable.
 * 
 * Executables are considered similar if they share similar functions, as determined by the BSim similarity metric.
 * Functions that are too common (high hitcount) or are too small (low self signficance) are not included
 * in the score.  A score of 1.0 means that all functions included in the score are shared between the two
 * executables and each have a (function) similarity of 1.0.
 * 
 * The script also computes a "library" score, which achieves 1.0 if the functions in the smaller of the two
 * executables all have a perfect match in the bigger executable.  The bigger executable may have many functions
 * with no match in the smaller executable.
 * 
 * For larger databases, repeated runs of this script can be made more efficient by allowing it to cache executable
 * "self-scores" between runs. Uncomment one of two lines instantiating the {@link ScoreCaching} object below. The
 * cache can be stored in the local file system or in an additional table/column in the BSim database.
 */
public class CompareExecutablesScript extends GhidraScript {

	private ExecutableComparison exeCompare;

	@Override
	protected void run() throws Exception {
		String urlString = askString("Enter BSim database URL", "URL: ");
		String execName =
			askString("Enter name of executable to compare against database", "Name: ");
		URL url = BSimClientFactory.deriveBSimURL(urlString);
		try (FunctionDatabase database = BSimClientFactory.buildClient(url, true)) {
			QueryExeInfo exeInfo = new QueryExeInfo();
			exeInfo.filterExeName = execName;
			ResponseExe exeResult = exeInfo.execute(database);
			if (exeResult == null) {
				String message = database.getLastError() != null ? database.getLastError().message
						: "Unrecoverable error";
				throw new IOException(message);
			}
			else if (exeResult.recordCount == 0) {
				throw new InvalidParameterException(
					"Executable " + execName + " is not present in database");
			}
			else if (exeResult.recordCount > 1) {
				println("Multiple executables with the name - " + execName);
				ExecutableRecord exeRecord = exeResult.records.get(0);
				print("Using ");
				println(exeRecord.printRaw());
			}
			String baseMd5 = exeResult.records.get(0).getMd5();

			ScoreCaching cache = null;		// If null, self scores will not be cached

			// Scores can be cached in the local file system by using FileScoreCaching
			// cache = new FileScoreCaching("/tmp/test_scorecacher.txt");

			// Scores can be cached in a dedicated table within the database by using TableScoreCaching
			// TableScoreCaching is currently only supported for the PostgreSQL back-end.
			// cache = new TableScoreCaching(database);

			exeCompare = new ExecutableComparison(database, 1000000, baseMd5, cache, monitor);
			// Its possible to specify the executables to compare with the base executable by
			// specifying their md5 hashes directly.
			//		exeCompare.addExecutable("22222222222222222222222222222222");	// 32 hex-digit string
			//		exeCompare.addExecutable("33333333333333333333333333333333");

			// Otherwise specify that we should compare the base executable against all executables
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
