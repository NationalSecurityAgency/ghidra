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
import ghidra.xml.XmlPullParser;

public class ResponseCluster extends QueryResponseRecord {

	public List<ClusterNote> notes;
	public QueryCluster query;

	public ResponseCluster(QueryCluster q) {
		super("responsecluster");
		notes = new ArrayList<ClusterNote>();
		query = q;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		query.manage.populateExecutableXref();	// Make cross-references are pregenerated
		fwrite.append('<').append(name).append(">\n");
		Iterator<ClusterNote> iter = notes.iterator();
		while (iter.hasNext()) {
			iter.next().saveXml(fwrite);
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		Map<Integer, ExecutableRecord> exeMap = query.manage.generateExecutableXrefMap();
		parser.start(name);
		while (parser.peek().isStart()) {
			ClusterNote newnote = new ClusterNote();
			newnote.restoreXml(parser, query.manage, exeMap);
			notes.add(newnote);
		}
		parser.end();
	}

}
