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

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * For specific functions, query for the list of vectors that are similar to a functions vector,
 * without recovering the descriptions of functions that instantiate these vectors.
 *
 */
public class QueryNearestVector extends BSimQuery<ResponseNearestVector> {

	public DescriptionManager manage;		// Functions that should be queried
	public ResponseNearestVector nearresponse;
	public double thresh;					// Similarity threshold for query
	public double signifthresh;				// Significance threshold for query
	public int vectormax;					// Maximum number of unique vectors returned
	
	public QueryNearestVector() {
		super("querynearestvector");
		thresh = QueryNearest.DEFAULT_SIMILARITY_THRESHOLD;
		signifthresh = QueryNearest.DEFAULT_SIGNIFICANCE_THRESHOLD;
		vectormax = 0;		// 0 indicates "no limit"
		manage = new DescriptionManager();
	}
	
	
	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = nearresponse = new ResponseNearestVector(this);
	}

	@Override
	public DescriptionManager getDescriptionManager() {
		return manage;
	}

	@Override
	public QueryNearestVector getLocalStagingCopy() {
		QueryNearestVector newq = new QueryNearestVector();
		newq.thresh = thresh;
		newq.signifthresh = signifthresh;
		newq.vectormax = vectormax;
		return newq;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		manage.saveXml(fwrite);
		fwrite.append("<simthresh>").append(Double.toString(thresh)).append("</simthresh>\n");
		fwrite.append("<signifthresh>").append(Double.toString(signifthresh)).append("</signifthresh>\n");
		if (vectormax != 0)
			fwrite.append("<vectormax>").append(SpecXmlUtils.encodeSignedInteger(vectormax)).append("</vectormax>\n");
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		vectormax = 0;			// Default
		parser.start(name);
		manage.restoreXml(parser, vectorFactory);
		parser.start("simthresh");
		thresh = Double.parseDouble(parser.end().getText());
		parser.start("signifthresh");
		signifthresh = Double.parseDouble(parser.end().getText());
		while (parser.peek().isStart()) {
			XmlElement el = parser.start();
			if (el.getName().equals("vectormax"))
				vectormax = SpecXmlUtils.decodeInt(parser.end().getText());
			else
				throw new LSHException("Unknown tag: "+el.getName());

		}
		parser.end();
	}

}
