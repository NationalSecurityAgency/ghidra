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
package ghidra.features.bsim.query.protocol;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlPullParser;

/**
 * Response to a QueryNearestVector request. It provides basic stats on the number of matching vectors and functions.
 * Only a list of the matching vectors is returned, not the detailed FunctionDescription records of matches.
 * Results are returned as SimilarityVectorResult objects, which cross-reference the original function queried and
 * any similar vectors.
 *
 */
public class ResponseNearestVector extends QueryResponseRecord {
	public int totalvec;			// Total vectors queried
	public int totalmatch;			// Total functions matched
	public int uniquematch;			// Total vectors with a unique function match
	public List<SimilarityVectorResult> result;
	public QueryNearestVector qnear;

	public ResponseNearestVector(QueryNearestVector q) {
		super("responsenearestvec");
		result = new ArrayList<SimilarityVectorResult>();
		qnear = q;
	}

	@Override
	public void sort() {
		for (SimilarityVectorResult res : result) {
			res.sortNotes();
		}
	}

	@Override
	public void mergeResults(QueryResponseRecord subresponse) {
		ResponseNearestVector subnearest = (ResponseNearestVector) subresponse;
		totalvec += subnearest.totalvec;
		totalmatch += subnearest.totalmatch;
		uniquematch += subnearest.uniquematch;
		result.addAll(subnearest.result);
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		qnear.manage.populateExecutableXref();
		fwrite.append('<').append(name).append(">\n");
		fwrite.append(" <tvec>")
			.append(SpecXmlUtils.encodeSignedInteger(totalvec))
			.append("</tvec>\n");
		fwrite.append(" <tmatch>")
			.append(SpecXmlUtils.encodeSignedInteger(totalmatch))
			.append("</tmatch>\n");
		fwrite.append(" <umatch>")
			.append(SpecXmlUtils.encodeSignedInteger(uniquematch))
			.append("</umatch>\n");
		Iterator<SimilarityVectorResult> iter = result.iterator();
		while (iter.hasNext()) {
			iter.next().saveXml(fwrite);
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		parser.start(name);
		parser.start("tvec");
		totalvec = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("tmatch");
		totalmatch = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("umatch");
		uniquematch = SpecXmlUtils.decodeInt(parser.end().getText());
		Map<Integer, ExecutableRecord> exeMap = qnear.manage.generateExecutableXrefMap();
		while (parser.peek().isStart()) {
			SimilarityVectorResult res = new SimilarityVectorResult();
			res.restoreXml(parser, vectorFactory, qnear.manage, exeMap);
			result.add(res);
		}
		parser.end();
	}

}
