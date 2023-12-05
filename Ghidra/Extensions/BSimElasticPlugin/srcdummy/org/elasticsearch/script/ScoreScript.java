/* ###
 * IP: GHIDRA
 * NOTE: Dummy placeholder for elasticsearch class
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
package org.elasticsearch.script;

import java.io.IOException;
import java.util.Map;

import org.elasticsearch.search.lookup.SearchLookup;

public abstract class ScoreScript {
	public ScoreScript(Map<String, Object> params, SearchLookup searchLookup, DocReader docReader) {

	}

	public static class ExplanationHolder {

	}

	public static final ScriptContext<ScoreScript.Factory> CONTEXT = null;

	public interface Factory extends ScriptFactory {
		LeafFactory newFactory(Map<String, Object> params, SearchLookup lookup);
	}

	public interface LeafFactory {
		boolean needs_score();

		ScoreScript newInstance(DocReader reader) throws IOException;
	}

	public int _getDocId() {
		return 0;
	}

	public abstract double execute(ExplanationHolder explanation);
}
