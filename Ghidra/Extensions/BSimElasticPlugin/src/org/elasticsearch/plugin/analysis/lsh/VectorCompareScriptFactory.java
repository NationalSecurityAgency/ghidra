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
package org.elasticsearch.plugin.analysis.lsh;

import java.io.*;
import java.util.Map;

import org.apache.lucene.document.Document;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.script.*;
import org.elasticsearch.script.ScoreScript.LeafFactory;
import org.elasticsearch.search.lookup.SearchLookup;

import generic.lsh.vector.LSHVector;
import generic.lsh.vector.VectorCompare;
import ghidra.features.bsim.query.elastic.Base64VectorFactory;

public class VectorCompareScriptFactory implements ScoreScript.Factory {

	public final static String SCRIPT_NAME = "lsh_compare";
	public final static String FEATURES_NAME = "{\"features\":\"";

	@Override
	public boolean isResultDeterministic() {
		return true;
	}

	@Override
	public LeafFactory newFactory(Map<String, Object> params, SearchLookup lookup) {
		return new VectorCompareLeafFactory(params, lookup);
	}

	private static class VectorCompareLeafFactory implements LeafFactory {

		private final Map<String, Object> params;
		private final SearchLookup lookup;
		private LSHVector baseVector;			// Vector being compared to everything
		private final double simthresh;				// Similarity threshold
		private final double sigthresh;				// Significance threshold
		private final Base64VectorFactory vectorFactory;	// Factory used for this particular query

		private VectorCompareLeafFactory(Map<String, Object> params, SearchLookup lookup) {
			this.params = params;
			this.lookup = lookup;
			vectorFactory = AnalysisLSHPlugin.getVectorFactory((String) params.get("indexname"));
			simthresh = (Double) params.get("simthresh");
			sigthresh = (Double) params.get("sigthresh");
			StringReader reader = new StringReader((String) params.get("vector"));
			try {
				baseVector = vectorFactory.restoreVectorFromBase64(reader,
					Base64VectorFactory.allocateBuffer());
			}
			catch (IOException e) {
				baseVector = null;
			}
		}

		@Override
		public boolean needs_score() {
			return false;
		}

		private static int scanForFeatures(byte[] buffer, int offset) throws IOException {
			int i = 0;
			while (i < FEATURES_NAME.length()) {
				char curChar = FEATURES_NAME.charAt(i);
				int val = buffer[offset];
				if (val == curChar) {
					i += 1;
					offset += 1;
				}
				else if (val == ' ' || val == '\t') {
					offset += 1;
				}
				else {
					throw new IOException("Document is missing \"features\"");
				}
			}
			return offset;
		}

		private static int scanForLength(BytesRef byteRef, int startOffset) throws IOException {
			int finalLength = 0;
			int maxLength = byteRef.length - (startOffset - byteRef.offset);
			while (finalLength < maxLength) {
				if (byteRef.bytes[finalLength + startOffset] == '\"') {
					break;
				}
				finalLength += 1;
			}
			if (finalLength == byteRef.length) {
				throw new IOException("Document does not contain complete \"features\"");
			}
			return finalLength;
		}

		@Override
		public ScoreScript newInstance(DocReader docReader) throws IOException {
			return new ScoreScript(params, lookup, docReader) {
				@Override
				public double execute(ExplanationHolder explanation) {
					try {
						DocValuesDocReader dvReader = (DocValuesDocReader) docReader;
						Document document =
							dvReader.getLeafReaderContext().reader().document(_getDocId());
						BytesRef byteRef = document.getField("_source").binaryValue();
						int valOffset = scanForFeatures(byteRef.bytes, byteRef.offset);
						int finalLength = scanForLength(byteRef, valOffset);
						InputStream inputStream =
							new ByteArrayInputStream(byteRef.bytes, valOffset, finalLength);
						Reader reader = new InputStreamReader(inputStream);
						// Should be sharing the VectorCompare between different calls
						// but apparently this routine needs to be thread safe, so we allocate it per call
						VectorCompare vectorCompare = new VectorCompare();
						LSHVector curVec = vectorFactory.restoreVectorFromBase64(reader,
							Base64VectorFactory.allocateBuffer());
						double sim = baseVector.compare(curVec, vectorCompare);
						if (sim <= simthresh) {
							return 0.0;
						}
						double sig = vectorFactory.calculateSignificance(vectorCompare);
						if (sig <= sigthresh) {
							return 0.0;
						}
						return sim;
					}
					catch (IOException e) {
						return 0.0;
					}
				}
			};
		}
	}
}
