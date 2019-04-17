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
package ghidra.app.util.recognizer;

import ghidra.util.classfinder.ClassSearcher;

import java.util.*;

public class RecognizerService {
	private static final Comparator<Recognizer> DESCENDING = new Comparator<Recognizer>() {
		public int compare(Recognizer o1, Recognizer o2) {
			return o2.getPriority() - o1.getPriority();
		}
	};

	public static List<Recognizer> getAllRecognizers() {
		List<Recognizer> results = new ArrayList<Recognizer>();
		List<Recognizer> allRecognizers = getAllRecognizersHelper();
		for (Recognizer Recognizer : allRecognizers) {
			results.add(Recognizer);
		}
		Collections.sort(results, DESCENDING);
		return results;
	}

	private static List<Recognizer> getAllRecognizersHelper() {
		return new ArrayList<Recognizer>(ClassSearcher.getInstances(Recognizer.class));
	}
}
