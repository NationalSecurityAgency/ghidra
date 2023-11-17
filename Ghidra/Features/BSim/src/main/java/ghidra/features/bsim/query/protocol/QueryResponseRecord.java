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
import ghidra.xml.XmlPullParser;

// A database query response record that can be serialized

public abstract class QueryResponseRecord {
	
	protected final String name;

	protected QueryResponseRecord(String name) {
		this.name = name;
	}
	
	public String getName() { return name; }
	
	public abstract void saveXml(Writer fwrite) throws IOException;
	
	public abstract void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException;

	public DescriptionManager getDescriptionManager() { return null; }

	/**
	 * @return a partial clone of this query suitable for holding local stages of the query via StagingManager
	 */
	public QueryResponseRecord getLocalStagingCopy() { return null; }
	
	/**
	 * Combine partial results from subresponse into this global response
	 * @param subresponse the partial response to merge into this
	 * @throws LSHException for errors performing the merge
	 */
	public void mergeResults(QueryResponseRecord subresponse) throws LSHException {
		// Must subclasses don't need to do anything
	}

	/**
	 * Perform any preferred sorting on the result of a query
	 */
	public void sort() {
		// Must subclasses don't need to do this
	}
}
