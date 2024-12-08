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
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Request that a BSim database either drop or build its main vector index
 *
 */
public class AdjustVectorIndex extends BSimQuery<ResponseAdjustIndex> {

	public boolean doRebuild;			// true if vector index should be rebuilt, false if it should be dropped
	public ResponseAdjustIndex adjustresponse;
	
	public AdjustVectorIndex() {
		super("adjustindex");
		doRebuild = false;
	}
	
	/* (non-Javadoc)
	 * @see ghidra.query.protocol.QueryResponseRecord#buildResponseTemplate()
	 */
	public void buildResponseTemplate() {
		if (response == null)
			response = adjustresponse = new ResponseAdjustIndex();
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name);
		fwrite.append(" rebuild=\"");
		fwrite.append(SpecXmlUtils.encodeBoolean(doRebuild));
		fwrite.append("\"/>\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		XmlElement el = parser.start(name);
		doRebuild = SpecXmlUtils.decodeBoolean(el.getAttribute("rebuild"));
		parser.end();
	}

}
