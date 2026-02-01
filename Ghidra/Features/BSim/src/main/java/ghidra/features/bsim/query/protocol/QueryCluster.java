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
import ghidra.xml.XmlPullParser;

public class QueryCluster extends BSimQuery<ResponseCluster> {

	public final DescriptionManager manage;		// Functions that should be queried as cluster roots
	public ResponseCluster clusterresponse;
	public double thresh;					// Similarity limit of the cluster
	public double signifthresh;				// Significance limit of the cluster
	public int vectormax;					// Maximum number of vector results per function
	
	public QueryCluster() {
		super("querycluster");
		manage = new DescriptionManager();
		thresh = 0.9;					// Some reasonable defaults
		signifthresh = 0.0;
		vectormax = 50;
	}
	
	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = clusterresponse = new ResponseCluster(this);
	}

	@Override
	public DescriptionManager getDescriptionManager() {
		return manage;
	}

	@Override
	public QueryCluster getLocalStagingCopy() {
		QueryCluster newc = new QueryCluster();
		newc.thresh = thresh;
		newc.signifthresh = signifthresh;
		newc.vectormax = vectormax;
		return newc;
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		manage.saveXml(fwrite);
		fwrite.append("<simthresh>").append(Double.toString(thresh)).append("</simthresh>\n");
		fwrite.append("<signifthresh>").append(Double.toString(signifthresh)).append("</signifthresh>\n");
		fwrite.append("<max>").append(SpecXmlUtils.encodeSignedInteger(vectormax)).append("</max>\n");
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		parser.start(name);
		manage.restoreXml(parser, vectorFactory);
		parser.start("simthresh");
		thresh = Double.parseDouble(parser.end().getText());
		parser.start("signifthresh");
		signifthresh = Double.parseDouble(parser.end().getText());
		parser.start("max");
		vectormax = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.end();
	}

}
