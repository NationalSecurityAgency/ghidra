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
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlPullParser;

/**
 * Response to a QueryNearest request.  A full description in terms of ExecutableRecords and FunctionDescriptions
 * is returned.  The linked list of SimilarityResults explicitly describes the similarities between the functions
 * in the original request and the new functions being returned.  A SimilarityResult cross-references
 * FunctionDescription objects between the request DescriptionManager and this response object's DescriptionManager 
 *
 */
public class ResponseNearest extends QueryResponseRecord {

	public int totalfunc;			// Total functions queried
	public int totalmatch;			// Total number of functions matched
	public int uniquematch;			// Total number of functions matched uniquely
	public final DescriptionManager manage;	// The collection of matching functions
	public List<SimilarityResult> result;		// Description of similarities
	public QueryNearest qnear;		// Original query

	public ResponseNearest(QueryNearest q) {
		super("responsenearest");
		manage = new DescriptionManager();
		result = new ArrayList<SimilarityResult>();
		totalfunc = 0;
		totalmatch = 0;
		uniquematch = 0;
		qnear = q;
	}

	@Override
	public void sort() {
		for (SimilarityResult sim : result)
			sim.sortNotes();
	}

	@Override
	public void mergeResults(QueryResponseRecord subresponse) throws LSHException {
		ResponseNearest subnearest = (ResponseNearest) subresponse;
		if (totalfunc == 0)
			manage.transferSettings(subnearest.manage); // Transfer settings first time through
		totalfunc += subnearest.totalfunc;
		totalmatch += subnearest.totalmatch;
		uniquematch += subnearest.uniquematch;
		result.addAll(subnearest.result);

		// Substitute the above result.addAll line with the commented code below for RegressionTestQuery test of staging
//		for(SimilarityResult simres : subnearest.result) {
//			SimilarityResult newsimres = new SimilarityResult();
//			newsimres.setTransfer(simres, qnear.manage, manage, false);
//			result.add(newsimres);
//		}
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		manage.populateExecutableXref();
		qnear.manage.populateExecutableXref();
		fwrite.append('<').append(name).append(">\n");
		fwrite.append(" <tfunc>")
			.append(SpecXmlUtils.encodeSignedInteger(totalfunc))
			.append("</tfunc>\n");
		fwrite.append(" <tmatch>")
			.append(SpecXmlUtils.encodeSignedInteger(totalmatch))
			.append("</tmatch>\n");
		fwrite.append(" <umatch>")
			.append(SpecXmlUtils.encodeSignedInteger(uniquematch))
			.append("</umatch>\n");
		manage.saveXml(fwrite);
		Iterator<SimilarityResult> iter = result.iterator();
		while (iter.hasNext()) {
			iter.next().saveXml(fwrite);
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		parser.start(name);
		parser.start("tfunc");
		totalfunc = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("tmatch");
		totalmatch = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("umatch");
		uniquematch = SpecXmlUtils.decodeInt(parser.end().getText());
		manage.restoreXml(parser, vectorFactory);
		Map<Integer, ExecutableRecord> qMap = qnear.manage.generateExecutableXrefMap();
		Map<Integer, ExecutableRecord> rMap = manage.generateExecutableXrefMap();
		while (parser.peek().isStart()) {
			SimilarityResult res = new SimilarityResult();
			res.restoreXml(parser, qnear.manage, manage, qMap, rMap);
			result.add(res);
		}
		parser.end();
	}
}
