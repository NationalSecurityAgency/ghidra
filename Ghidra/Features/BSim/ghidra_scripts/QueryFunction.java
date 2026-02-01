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
// Example of querying a BSim database about a single function
//@category BSim

import java.net.URL;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.program.model.listing.Function;

public class QueryFunction extends GhidraScript {

	private static final int MATCHES_PER_FUNC = 10;
	private static final double SIMILARITY_BOUND = 0.7;
	private static final double CONFIDENCE_BOUND = 0.0;

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			return;
		}
		Function func = this.getFunctionContaining(this.currentAddress);
		if (func == null) {
			popup("No function selected!");
			return;
		}

		String DATABASE_URL = askString("Enter Database URL", "URL");
		URL url = BSimClientFactory.deriveBSimURL(DATABASE_URL);
		try (FunctionDatabase database = BSimClientFactory.buildClient(url, false)) {
			if (!database.initialize()) {
				println(database.getLastError().message);
				return;
			}

			GenSignatures gensig = new GenSignatures(false);
			try {
				gensig.setVectorFactory(database.getLSHVectorFactory());
				gensig.openProgram(currentProgram, null, null, null, null, null);

				DescriptionManager manager = gensig.getDescriptionManager();
				gensig.scanFunction(func);

				QueryNearest query = new QueryNearest();
				query.manage = manager;
				query.max = MATCHES_PER_FUNC;
				query.thresh = SIMILARITY_BOUND;
				query.signifthresh = CONFIDENCE_BOUND;

				ResponseNearest response = query.execute(database);
				if (response == null) {
					println(database.getLastError().message);
					return;
				}
				Iterator<SimilarityResult> iter = response.result.iterator();
				StringBuffer buf = new StringBuffer();
				while (iter.hasNext()) {
					SimilarityResult sim = iter.next();
					FunctionDescription base = sim.getBase();
					ExecutableRecord exe = base.getExecutableRecord();
					buf.append("\nExecutable: ")
							.append(exe.getNameExec())
							.append("\nFunction: ")
							.append(base.getFunctionName())
							.append('\n');
					Iterator<SimilarityNote> subiter = sim.iterator();
					while (subiter.hasNext()) {
						SimilarityNote note = subiter.next();
						FunctionDescription fdesc = note.getFunctionDescription();
						ExecutableRecord exerec = fdesc.getExecutableRecord();
						buf.append("  Executable: ");
						buf.append(exerec.getNameExec())
								.append("\n  Matching Function name: ")
								.append(fdesc.getFunctionName());
						buf.append("\n  Similarity: ").append(note.getSimilarity());
						buf.append("\n  Significance:  ").append(note.getSignificance());
						buf.append("\n\n");
					}
				}
				println(buf.toString());
			}
			finally {
				gensig.dispose();
			}
		}
	}

}
