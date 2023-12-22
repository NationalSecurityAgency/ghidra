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
import ghidra.xml.XmlPullParser;

/**
 * Request the DatabaseInformation object for a specific BSim database.
 *
 */
public class QueryInfo extends BSimQuery<ResponseInfo> {
	public ResponseInfo inforesponse;
	
	public QueryInfo() {
		super("queryinfo");
	}
	
	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = inforesponse = new ResponseInfo();
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("<").append(name).append("/>\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		// Nothing to do
	}

}
