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
 * Query nearest matches within database to a set of functions
 *
 */
public class QueryNearest extends BSimQuery<ResponseNearest> {

	/**
	 * The default value for the similarity threshold. This
	 * threshold is for how similar the potential function is. This is a value from 0.0 to 1.0.
	 */
	public static final double DEFAULT_SIMILARITY_THRESHOLD = 0.7;

	/**
	 * The default value for the significance threshold.  This
	 * threshold is for how significant the match is (for example, smaller function matches
	 * are less significant).  Higher is more significant.  There is no upper bound.
	 */
	public static final double DEFAULT_SIGNIFICANCE_THRESHOLD = 0.0;

	/**
	 * The default value for the maximum number of similar functions to return 
	 * <b>for a given input function</b>
	 */
	public static final int DEFAULT_MAX_MATCHES = 100;

	public DescriptionManager manage;		// Functions that should be queried
	public ResponseNearest nearresponse;
	public double thresh;					// Similarity threshold for query
	public double signifthresh;				// Significance threshold for query
	public int max;							// Maximum number of results to return (per function)
	public int vectormax;					// Maximum number of unique vectors that can be returned
	public boolean fillinCategories;		// Query for categories of any returned executable
	public BSimFilter bsimFilter;		    // Filters for the query
	
	public QueryNearest() {
		super("querynearest");
		thresh = DEFAULT_SIMILARITY_THRESHOLD;
		signifthresh = DEFAULT_SIGNIFICANCE_THRESHOLD;
		max = DEFAULT_MAX_MATCHES;
		vectormax = 0;				// 0 indicates "no limit"
		fillinCategories = true;
		bsimFilter = null;
		manage = new DescriptionManager();
	}
	
	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = nearresponse = new ResponseNearest(this);
	}

	@Override
	public DescriptionManager getDescriptionManager() {
		return manage;
	}

	@Override
	public QueryNearest getLocalStagingCopy() {
		QueryNearest newq = new QueryNearest();
		newq.thresh = thresh;
		newq.signifthresh = signifthresh;
		newq.max = max;
		newq.vectormax = vectormax;
		newq.fillinCategories = fillinCategories;
		if (bsimFilter != null)
			newq.bsimFilter = bsimFilter.clone();
		return newq;
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		manage.saveXml(fwrite);
		fwrite.append("<simthresh>").append(Double.toString(thresh)).append("</simthresh>\n");
		fwrite.append("<signifthresh>").append(Double.toString(signifthresh)).append("</signifthresh>\n");
		fwrite.append("<max>").append(SpecXmlUtils.encodeSignedInteger(max)).append("</max>\n");
		if (vectormax != 0)
			fwrite.append("<vectormax>").append(SpecXmlUtils.encodeSignedInteger(vectormax)).append("</vectormax>\n");
		if (!fillinCategories)
			fwrite.append("<categories>false</categories>\n");
		if (bsimFilter!=null)
			bsimFilter.saveXml(fwrite);
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		vectormax = 0;			// Default
		fillinCategories = true;	// Default
		parser.start(name);
		manage.restoreXml(parser, vectorFactory);
		parser.start("simthresh");
		thresh = Double.parseDouble(parser.end().getText());
		parser.start("signifthresh");
		signifthresh = Double.parseDouble(parser.end().getText());
		parser.start("max");
		max = SpecXmlUtils.decodeInt(parser.end().getText());
		while (parser.peek().isStart()) {
			XmlElement el = parser.peek();
			if (el.getName().equals("vectormax")) {
				parser.start();
				vectormax = SpecXmlUtils.decodeInt(parser.end().getText());
			}
			else if (el.getName().equals("categories")) {
				parser.start();
				fillinCategories = SpecXmlUtils.decodeBoolean(parser.end().getText());
			}
			else if (el.getName().equals("exefilter")) {
				bsimFilter = new BSimFilter();
				bsimFilter.restoreXml(parser);
			}
			else
				throw new LSHException("Unknown tag: "+el.getName());
				
		}
		parser.end();
	}

}
