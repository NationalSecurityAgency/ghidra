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
import java.util.ArrayList;
import java.util.List;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Request all functions described by a particular feature vector. Vectors are specified
 * by a known id, and multiple vectors can be specified at once.
 */
public class QueryVectorMatch extends BSimQuery<ResponseVectorMatch> {

	// Default maximum number of functions to return that match a single vector id
	public static final int DEFAULT_MAX_FUNCTIONS = 200;
	public ResponseVectorMatch matchresponse;
	public int max;							// Maximum number of results to return (per vector id)
	public boolean fillinCategories;		// Query for categories of any returned executable
	public BSimFilter bsimFilter;		    // Filters for the query
	public List<Long> vectorIds;		// List of vector ids to query for

	public QueryVectorMatch() {
		super("queryvectormatch");
		max = DEFAULT_MAX_FUNCTIONS;
		fillinCategories = true;
		bsimFilter = null;
		vectorIds = new ArrayList<Long>();
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null) {
			response = matchresponse = new ResponseVectorMatch();
		}
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		fwrite.append("<max>").append(SpecXmlUtils.encodeSignedInteger(max)).append("</max>\n");
		if (!fillinCategories) {
			fwrite.append("<categories>false</categories>\n");
		}
		if (bsimFilter != null) {
			bsimFilter.saveXml(fwrite);
		}
		for (Long id : vectorIds) {
			fwrite.append("<id>0x")
				.append(SpecXmlUtils.encodeUnsignedInteger(id))
				.append(
					"</id>\n");
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		fillinCategories = true;	// Default
		parser.start(name);
		parser.start("max");
		max = SpecXmlUtils.decodeInt(parser.end().getText());
		while (parser.peek().isStart()) {
			XmlElement el = parser.peek();
			if (el.getName().equals("categories")) {
				parser.start();
				fillinCategories = SpecXmlUtils.decodeBoolean(parser.end().getText());
			}
			else if (el.getName().equals("exefilter")) {
				bsimFilter = new BSimFilter();
				bsimFilter.restoreXml(parser);
			}
			else if (el.getName().equals("id")) {
				parser.start();
				long val = SpecXmlUtils.decodeLong(parser.end().getText());
				vectorIds.add(val);
			}
			else {
				throw new LSHException("Unknown tag: " + el.getName());
			}

		}
		parser.end();
	}

}
