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
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.xml.XmlPullParser;

// A database query that can be serialized

/**
 * {@link BSimQuery} facilitates all BSim {@link FunctionDatabase} queries
 * which when executed provide a specific {@link QueryResponseRecord}.
 *
 * @param <R> The {@link QueryResponseRecord} response implementation class
 */
public abstract class BSimQuery<R extends QueryResponseRecord> {

	// TODO: direct manipulation of instance fields for all implementations
	// should be utilize tailored constructor arguments

	// TODO: restoreXml method should be replaced by Xml-based constructor for each implementation

	protected final String name;
	protected R response;
	
	public BSimQuery(String name) {
		this.name = name;
		response = null;
	}
	
	/**
	 * Executes this query via the {@link FunctionDatabase#query(BSimQuery)} method.
	 * The use of this method is preferred due to its type enforcement on the returned
	 * response object. 
	 * @param database BSim function database to be queried
	 * @return query response or null on error (see {@link FunctionDatabase#getLastError()}).
	 */
	@SuppressWarnings("unchecked")
	public final R execute(FunctionDatabase database) {
		return (R) database.query(this);
	}

	public void clearResponse() {
		response = null;
	}
	
	public R getResponse() {
		return response;
	}
	
	public String getName() {
		return name;
	}
	
	public void buildResponseTemplate() {
		// Any response subclass doesn't need to implement this
	}
	
	public abstract void saveXml(Writer fwrite) throws IOException;
	
	public abstract void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException;

	public DescriptionManager getDescriptionManager() { return null; }

	/**
	 * @return a partial clone of this query suitable for holding local stages of the query via StagingManager
	 */
	public BSimQuery<?> getLocalStagingCopy() {
		return null;
	}

	/**
	 * Restore a query from a stream
	 * @param parser is the XmlPullParser already queued up with the stream to process
	 * @param vectorFactory is used to generate any vector objects from the XML
	 * @return one of the Query* instances derived from QueryResponseRecord
	 * @throws LSHException for errors creating the command
	 */
	public static BSimQuery<?> restoreQuery(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		String mainName = parser.peek().getName();
		BSimQuery<?> query;
		if (mainName.equals("querynearest")) {
			query = new QueryNearest();
		}
		else if (mainName.equals("querynearestvector")) {
			query = new QueryNearestVector();
		}
		else if (mainName.equals("insert")) {
			query = new InsertRequest();
		}
		else if (mainName.equals("queryinfo")) {
			query = new QueryInfo();
		}
		else if (mainName.equals("update")) {
			query = new QueryUpdate();
		}
		else if (mainName.equals("queryname")) {
			query = new QueryName();
		}
		else if (mainName.equals("delete")) {
			query = new QueryDelete();
		}
		else if (mainName.equals("createdatabase")) {
			query = new CreateDatabase();
		}
		else if (mainName.equals("querychildren")) {
			query = new QueryChildren();
		}
		else if (mainName.equals("querycluster")) {
			query = new QueryCluster();
		}
		else if (mainName.equals("querypair")) {
			query = new QueryPair();
		}
		else if (mainName.equals("installcategory")) {
			query = new InstallCategoryRequest();
		}
		else if (mainName.equals("installmetadata")) {
			query = new InstallMetadataRequest();
		}
		else if (mainName.equals("installtag")) {
			query = new InstallTagRequest();
		}
		else if (mainName.equals("adjustindex")) {
			query = new AdjustVectorIndex();
		}
		else if (mainName.equals("passwordchange")) {
			query = new PasswordChange();
		}
		else if (mainName.equals("prewarmrequest")) {
			query = new PrewarmRequest();
		}
		else {
			throw new LSHException("Unknown query tag: "+mainName);
		}
		query.restoreXml(parser,vectorFactory);
		return query;
	}
}
