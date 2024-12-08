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
package ghidra.features.bsim.query.elastic;

import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import generic.lsh.vector.*;
import ghidra.features.bsim.gui.filters.FunctionTagBSimFilterType;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.client.*;
import ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.framework.client.ClientUtil;
import ghidra.util.xml.SpecXmlUtils;

/**
 * Implement the BSim database interface on top of an ElasticSearch back-end
 * ElasticSearch holds records as JSON documents.  Documents
 * are stored in a specific "index". The primary BSim document index/types are:
 *   executable/exe      is executable metadata corresponding to the ExecutableRecord object
 *   executable/function is function metadata corresponding to the FunctionDescription object
 *   vector/vector       is the main feature vector corresponding to an LSHVector object
 *   meta/meta           is a document containing the duplication count for a particular feature vector
 */
public class ElasticDatabase implements FunctionDatabase {

	public static final int LAYOUT_VERSION = 3;	// Version of the BSim schema within ElasticSearch as implemented
												// by this database implementation, so clients can detect
												// incompatible servers
	public static final int MAX_VECTOR_OVERALL = 9000;	// Max vectors return in one query (Note: index.max_result_window defaults to 10000)
	public static final int MAX_FUNCTION_WINDOW = 500;	// Max functions returned per window, when querying single executable
	public static final int MAX_FUNCTIONUPDATE_WINDOW = 500;	// Max functions updated in one window
	public static final int MAX_VECTORCOUNT_WINDOW = 100;	// Max vector meta documents returned in one mget
	public static final int MAX_VECTORDELETE_WINDOW = 100;	// Max vector or meta documents to delete/update in one bulk request
	public static final int MAX_FUNCTION_BULK = 200;		// Maximum functions ingested in one bulk request
	public static final int MAX_VECTOR_BULK = 200;			// Maximum vectors ingested in one bulk request

	private ElasticConnection connection;		// Low-level connection to the database
	private String userName = null;				// User name for server authentication
	private ConnectionType connectionType = ConnectionType.Unencrypted_No_Authentication;
	private DatabaseInformation info;			// Information about the active database
	private Base64VectorFactory vectorFactory;	// factory used to create BSim feature vectors
	private final BSimServerInfo serverInfo;    // NOTE: does not reflect the use of http vs https
	private final String baseURL;						// Base URL for connecting to elasticsearch, i.e. http://hostname:9200
	private final String repository;					// Name of the repository, prefix to all elasticsearch indices
	private Error lastError;					// Info on error caused by last action taken on this interface (null if no error)
	private Status status;						// status of the connection
	private boolean initialized;				// true if the connection has been successfully initialized

	/**
	 * Append a list of CategoryRecords as (part of) a JSON document to a StringBuilder
	 * Used as part of constructing JSON serialization of ExecutableRecords
	 * @param catRecords list of category records
	 * @param buffer for writing
	 */
	private static void appendCategoryTag(List<CategoryRecord> catRecords, StringBuilder buffer) {
		buffer.append("\"execategory\": [");
		if (catRecords != null) {
			boolean needsComma = false;
			for (CategoryRecord catrec : catRecords) {
				if (needsComma) {
					buffer.append(',');
				}
				else {
					needsComma = true;
				}
				buffer.append('\"');
				// Append type/value pair as concatendated strings separated by a TAB.
				// When sorting as strings, this should give the same order as sorted CategoryRecords
				buffer.append(catrec.getType())
						.append("\\t")
						.append(JSONObject.escape(catrec.getCategory()));
				buffer.append('\"');
			}
		}
		buffer.append(']');
	}

	/**
	 * Write an ExecutableRecord (meta-data about an executable) to the "executable" index.
	 * @param exeRecord is the record to write
	 * @param exeId is the unique id for the elasticsearch document
	 * @return true if the document gets created, return false is the document already exists
	 * @throws ElasticException if there are problems communicating with the server
	 */
	private boolean insertExecutableRecord(ExecutableRecord exeRecord, String exeId)
			throws ElasticException {
		StringBuilder builder = new StringBuilder();
		builder.append("{ \"md5\": \"").append(exeRecord.getMd5()).append("\", ");
		builder.append("\"name_exec\": \"")
				.append(JSONObject.escape(exeRecord.getNameExec()))
				.append("\", ");
		builder.append("\"architecture\": \"").append(exeRecord.getArchitecture()).append("\", ");
		builder.append("\"name_compiler\": \"").append(exeRecord.getNameCompiler()).append("\", ");
		builder.append("\"ingest_date\": ").append(exeRecord.getDate().getTime()).append(", ");
		if (exeRecord.getRepository() == null) {
			builder.append("\"repository\": null, ");
		}
		else {
			builder.append("\"repository\": \"")
					.append(JSONObject.escape(exeRecord.getRepository()))
					.append("\", ");
		}
		if (exeRecord.getPath() == null) {
			builder.append("\"path\": null");
		}
		else {
			builder.append("\"path\": \"")
					.append(JSONObject.escape(exeRecord.getPath()))
					.append("\"");
		}
		List<CategoryRecord> catrecs = exeRecord.getAllCategories();
		if (catrecs != null) {
			builder.append(", ");
			appendCategoryTag(catrecs, builder);
		}
		builder.append(", \"join_field\": \"exe\" }");
		StringBuilder pathbuilder = new StringBuilder();
		pathbuilder.append("executable/_doc/");
		pathbuilder.append(exeId);
		pathbuilder.append("?op_type=create");		// Do "create" operation, so we fail if document already exists
		JSONObject resp = connection.executeStatementExpectFailure(ElasticConnection.PUT,
			pathbuilder.toString(), builder.toString());
		JSONObject error = (JSONObject) resp.get("error");
		if (error != null) {
			String type = (String) error.get("type");
			if (type.startsWith("version_conflict")) {
				return false;			// Document already inserted
			}
			String reason = (String) error.get("reason");
			throw new ElasticException(reason);
		}
		return true;
	}

	/**
	 * Set the "document id" for an ExecutableRecord. This is currently the
	 * last 96-bits of the md5 hash of the executable encoded in base64
	 * @param manager is the container for the ExecutableRecord
	 * @param exeRecord has its key set
	 * @return the new RowKey
	 */
	private static RowKeyElastic updateKey(DescriptionManager manager, ExecutableRecord exeRecord) {
		if (exeRecord.getRowId() == null) {
			RowKeyElastic eKey = new RowKeyElastic(exeRecord.getMd5());
			manager.setExeRowId(exeRecord, eKey);
			return eKey;
		}
		return (RowKeyElastic) exeRecord.getRowId();
	}

	/**
	 * Generate a sorted list of the document ids of the children of a function
	 * @param manager is the container of the function
	 * @param funcRecord is the description of the function
	 * @return the list of document ids as Strings
	 */
	private static List<String> generateChildIds(DescriptionManager manager,
			FunctionDescription funcRecord) {
		List<CallgraphEntry> callgraphRecord = funcRecord.getCallgraphRecord();
		if (callgraphRecord == null) {
			return null;
		}
		List<String> res = new ArrayList<>(callgraphRecord.size());
		for (CallgraphEntry element : callgraphRecord) {
			FunctionDescription func = element.getFunctionDescription();
			ExecutableRecord exeRec = func.getExecutableRecord();
			RowKeyElastic eKey = updateKey(manager, exeRec);
			StringBuilder buffer = new StringBuilder();
			eKey.generateFunctionId(buffer, func);
			res.add(buffer.toString());
		}
		Collections.sort(res);
		return res;
	}

	/**
	 * Insert a range of FunctionDescription documents into the index.
	 * Documents are stored in the "executable" index
	 * @param manager is the container of the FunctionDescription objects
	 * @param exeRecord is the single executable containing the functions
	 * @param exeKey is the precomputed key of the executable
	 * @param exeId is the executable key encoded as a document id String
	 * @param iter is an iterator to the FunctionDescriptions to insert
	 * @param maxNumber is the (maximum) number of FunctionDescriptions to insert
	 * @throws ElasticException if there are problems communicating with the server
	 */
	private void insertFunctionRange(DescriptionManager manager, ExecutableRecord exeRecord,
			RowKeyElastic exeKey, String exeId, Iterator<FunctionDescription> iter, int maxNumber)
			throws ElasticException {
		StringBuilder builder = new StringBuilder();
		do {
			FunctionDescription desc = iter.next();
			builder.append("{ \"create\": { \"_index\": \"")
					.append(repository)
					.append("_executable\", ");
			builder.append("\"_id\": \"");
			exeKey.generateFunctionId(builder, desc);
			builder.append("\", \"routing\": \"");
			builder.append(exeId).append("\"}}\n");
			builder.append("{ \"name_func\": \"");
			builder.append(JSONObject.escape(desc.getFunctionName()));
			SignatureRecord sigRec = desc.getSignatureRecord();
			long vecid = 0;
			if (sigRec != null) {
				vecid = sigRec.getVectorId();
			}
			builder.append("\", \"id_signature\": \"");
			Base64Lite.encodeLongBase64(builder, vecid);
			builder.append("\", \"flags\": ").append(desc.getFlags());
			builder.append(", \"addr\": ").append(desc.getAddress());
			if (info.trackcallgraph) {
				List<String> vals = generateChildIds(manager, desc);
				if (vals != null) {
					builder.append(", \"childid\": [");
					boolean needComma = false;
					for (String val : vals) {
						if (needComma) {
							builder.append(',');
						}
						builder.append('\"').append(val).append('\"');
						needComma = true;
					}
					builder.append(" ]");
				}
			}
			builder.append(", \"join_field\": { ");
			builder.append("\"name\": \"function\", ");
			builder.append("\"parent\": \"");
			builder.append(exeId).append("\"}}\n");
			maxNumber -= 1;
			if (maxNumber <= 0) {
				break;
			}
		}
		while (iter.hasNext());
		connection.executeBulk("/_bulk", builder.toString());
	}

	/**
	 * Query for a single executable document based on the md5.  There should be 0 or 1 matching docs.
	 * @param md5 is the md5 string
	 * @return null or the "hit" portion of the response corresponding to the matching document
	 * @throws ElasticException for communication problems with the server
	 */
	private JSONObject queryMd5ExeMatch(String md5) throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append(
			"{ \"size\": 1, \"query\": { \"bool\": { \"filter\": { \"term\": { \"md5\": \"");
		buffer.append(md5).append("\" } } } } }");
		JSONObject resp = connection.executeStatement(ElasticConnection.GET, "executable/_search",
			buffer.toString());
		JSONObject hits = (JSONObject) resp.get("hits");
		JSONObject totalRec = (JSONObject) hits.get("total");
		long total = (Long) totalRec.get("value");
		if (total == 0) {
			return null;
		}
		JSONArray hitsArray = (JSONArray) hits.get("hits");
		return (JSONObject) hitsArray.get(0);
	}

	/**
	 * Query for function documents matching a given executable and a given function name
	 * @param exeId is the document id of the executable to match
	 * @param functionName is the name of the function
	 * @param maxDocuments is the maximum number of documents to return
	 * @return a list of JSON function documents
	 * @throws ElasticException for communication problems with the server
	 */
	private JSONArray queryFuncNameMatch(String exeId, String functionName, int maxDocuments)
			throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"size\": ").append(maxDocuments);
		buffer.append(", \"_source\": { \"excludes\": [ \"childid\" ] }");
		buffer.append(", \"query\": {");
		buffer.append("    \"bool\": {");
		buffer.append("      \"must\": {");
		buffer.append("        \"term\": {");
		buffer.append("          \"name_func\": \"");
		buffer.append(JSONObject.escape(functionName));
		buffer.append("\"} },");
		buffer.append("      \"filter\": {");
		buffer.append("        \"parent_id\": {");
		buffer.append("          \"type\": \"function\",");
		buffer.append("          \"id\": \"").append(exeId);
		buffer.append("\"} } } } }");
		JSONObject resp = connection.executeStatement(ElasticConnection.GET, "executable/_search",
			buffer.toString());
		JSONObject baseHits = (JSONObject) resp.get("hits");
		Object hitsArray = baseHits.get("hits");
		if (hitsArray == null) {
			return new JSONArray();
		}
		return (JSONArray) hitsArray;
	}

	/**
	 * Query for function documents matching a given executable,
	 * a given function name, and a given function address. These 3 things
	 * should always identify a function uniquely within the database, so at
	 * most 1 document should be returned
	 * @param exeId is the document id of the executable to match
	 * @param functionName is the name of the function to match
	 * @param address is the address of the function to match
	 * @return the JSON function document or null if none match
	 * @throws ElasticException for communication problems with the server
	 */
	private JSONObject queryFuncNameAddress(String exeId, String functionName, long address)
			throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"_source\": { \"excludes\": [ \"childid\" ] }");
		buffer.append(", \"query\": {");
		buffer.append("    \"bool\": {");
		buffer.append("      \"must\": {");
		buffer.append("        \"term\": {");
		buffer.append("          \"name_func\": \"");
		buffer.append(JSONObject.escape(functionName));
		buffer.append("\"},");
		buffer.append("        \"term\": {");
		buffer.append("           \"addr\": ").append(address);
		buffer.append("} },");
		buffer.append("      \"filter\": {");
		buffer.append("        \"parent_id\": {");
		buffer.append("          \"type\": \"function\",");
		buffer.append("          \"id\": \"").append(exeId);
		buffer.append("\"} } } } }");
		JSONObject resp = connection.executeStatement(ElasticConnection.GET, "executable/_search",
			buffer.toString());
		JSONObject baseHits = (JSONObject) resp.get("hits");
		JSONObject totalRec = (JSONObject) baseHits.get("total");
		long total = (Long) totalRec.get("value");
		if (total != 1) {
			return null;
		}
		JSONArray hitsArray = (JSONArray) baseHits.get("hits");
		return (JSONObject) hitsArray.get(0);
	}

	/**
	 * Query for a single executable given uniquely specifying information (ExeSpecifier).
	 * The exe document is retrieved from the database and parsed into an ExecutableRecord object.
	 * @param specifier is the uniquely specifying info about the executable
	 * @param manager is container for the final ExecutableRecord
	 * @return the matching ExecutableRecord or null if none is found
	 * @throws LSHException if there are problems adding the queried record to the container
	 * @throws ElasticException for communication problems with the server
	 */
	private ExecutableRecord findSingleExecutable(ExeSpecifier specifier,
			DescriptionManager manager) throws LSHException, ElasticException {
		if (specifier.exemd5 != null && specifier.exemd5.length() != 0) {
			JSONObject row = queryMd5ExeMatch(specifier.exemd5);
			if (row == null) {
				return null;
			}
			return makeExecutableRecord(manager, row);
		}
		if (StringUtils.isEmpty(specifier.exename)) {
			throw new LSHException("ExeSpecifier must provide either md5 or name");
		}
		return querySingleExecutable(manager, specifier.exename, specifier.arch,
			specifier.execompname);
	}

	/**
	 * Query for a single executable given uniquely specifying information (ExeSpecifier).
	 * A cache map is checked first for a previously recovered ExecutableRecord object.
	 * If not in the cache, the database is searched. If the executable is found, the ExecutableRecord
	 * is parsed from the database document, put into the cache, and returned to the user.
	 * @param specifier is the uniquely specifying info about the executable
	 * @param manager is container for the final ExecutableRecord
	 * @param nameMap is the cache of previously recovered records
	 * @return the matching ExecutableRecord or null if none is found
	 * @throws LSHException if there are problems adding the queried record to the container
	 * @throws ElasticException for communication problems with the server
	 */
	private ExecutableRecord findSingleExeWithMap(ExeSpecifier specifier,
			DescriptionManager manager, TreeMap<ExeSpecifier, ExecutableRecord> nameMap)
			throws LSHException, ElasticException {
		ExecutableRecord erec = nameMap.get(specifier);
		if (erec != null) {
			return erec;
		}
		erec = findSingleExecutable(specifier, manager);
		nameMap.put(specifier, erec);			// Cache ExecutableRecord in map, even if its null
		return erec;
	}

	/**
	 * Within the list of all executables sorted by md5 or name, query for executables
	 * from a specific window in this list.
	 * @param manager is the container to receive the ExecutableRecords
	 * @param exeList will have recovered ExecutableRecords appended to the end
	 * @param maxWindow is (maximum) number of executables in the window
	 * @param searchAfter is the (md5 or name) of the last executable before the window
	 *     or null if the first window is desired
	 * @param md5Order is true if executables are ordered by md5, false if ordered by name
	 * @param filter is an (optional) filter to apply to the list before constructing the window
	 * @throws ElasticException if there are errors querying the database
	 * @throws LSHException for problems creating the result set
	 */
	private void queryExecutables(DescriptionManager manager, List<ExecutableRecord> exeList,
			int maxWindow, String searchAfter, boolean md5Order, String filter)
			throws ElasticException, LSHException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"size\": ").append(maxWindow);
		buffer.append(", \"query\": {");
		buffer.append("  \"bool\": {");
		buffer.append("    \"must\": {");
		buffer.append("      \"exists\": { \"field\": \"md5\" } }");
		if (filter != null) {
			buffer.append(", ");
			buffer.append(filter);
		}
		buffer.append("}}, ");
		if (searchAfter != null) {
			buffer.append("\"search_after\": [ \"");
			buffer.append(JSONObject.escape(searchAfter));
			buffer.append("\"], ");
		}
		if (md5Order) {
			buffer.append("\"sort\": [ { \"md5\": \"asc\" } ] }");
		}
		else {
			buffer.append("\"sort\": [ { \"name_exec\": \"asc\" } ] }");
		}
		JSONObject resp = connection.executeStatement(ElasticConnection.GET, "executable/_search",
			buffer.toString());
		JSONObject baseHits = (JSONObject) resp.get("hits");
		JSONArray hitsArray = (JSONArray) baseHits.get("hits");
		for (Object element : hitsArray) {
			JSONObject exerow = (JSONObject) element;
			ExecutableRecord exeRecord = makeExecutableRecord(manager, exerow);
			exeList.add(exeRecord);
		}
	}

	/**
	 * Place the same query for executables as {@link #queryExecutables(DescriptionManager, List, int, String, boolean, String)}.
	 * Except we only return the count of matching records.
	 * @param filter is the option filter options for the count
	 * @return the number of matching executables matching the filter
	 * @throws ElasticException is there is a server-side issue with the query
	 */
	protected int countExecutables(String filter) throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"query\": {");
		buffer.append("  \"bool\": {");
		buffer.append("    \"must\": {");
		buffer.append("      \"exists\": { \"field\": \"md5\" } }");
		if (filter != null) {
			buffer.append(", ");
			buffer.append(filter);
		}
		buffer.append("}}}");
		JSONObject resp = connection.executeStatement(ElasticConnection.GET, "executable/_count",
			buffer.toString());
		Long res = (Long) resp.get("count");
		return res.intValue();
	}

	/**
	 * Query for a unique executable based on its name and possibly other metadata
	 * 
	 * @param manager is the container to store the result
	 * @param exeName is the name the executable must match
	 * @param arch is the architecture the executable must match (may be zero length)
	 * @param compilerName is the compiler name the executable must match (may be zero length)
	 * @return the unique resulting ExecutableRecord or null, if none or more than 1 is found
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems adding new records to the container
	 */
	private ExecutableRecord querySingleExecutable(DescriptionManager manager, String exeName,
			String arch, String compilerName) throws ElasticException, LSHException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"size\": 4,");
		buffer.append("  \"query\": {");
		buffer.append("  \"bool\": {");
		buffer.append("      \"must\": {");
		buffer.append("        \"term\": { \"name_exec\": \"")
				.append(JSONObject.escape(exeName))
				.append("\" } }");
		if (!StringUtils.isEmpty(arch) || !StringUtils.isEmpty(compilerName)) {
			buffer.append(",   \"filter\": {");
			buffer.append("      \"script\": {");
			buffer.append("        \"script\": {");
			buffer.append("          \"inline\": \"");
			if (StringUtils.isEmpty(arch)) {		// cname only
				buffer.append("doc['name_compiler'].value == params.comp");
			}
			else if (StringUtils.isEmpty(compilerName)) {	// arch only
				buffer.append("doc['architecture'].value == params.arch");
			}
			else {	// Both are provided
				buffer.append(
					"doc['name_compiler'].value == params.comp && doc['architecture'].value == params.arch");
			}
			buffer.append("\",");
			buffer.append("          \"params\": {");
			if (arch.length() != 0) {
				buffer.append(" \"arch\": \"").append(arch);
				if (!StringUtils.isEmpty(compilerName)) {
					buffer.append("\", ");
				}
				else {
					buffer.append("\" ");
				}
			}
			if (!StringUtils.isEmpty(compilerName)) {
				buffer.append(" \"comp\": \"").append(compilerName).append("\" ");
			}
			buffer.append("}}}}");
		}
		buffer.append("} } }");
		JSONObject resp = connection.executeStatement(ElasticConnection.GET, "executable/_search",
			buffer.toString());
		JSONObject baseHits = (JSONObject) resp.get("hits");
		JSONObject totalRec = (JSONObject) baseHits.get("total");
		long total = (Long) totalRec.get("value");
		if (total != 1) {
			return null;		// Either no results, or not unique
		}
		JSONArray hitsArray = (JSONArray) baseHits.get("hits");
		JSONObject exerow = (JSONObject) hitsArray.get(0);
		ExecutableRecord exerec = makeExecutableRecord(manager, exerow);
		return exerec;
	}

	/**
	 * Fill in hitcounts for a list of VectorResults by querying for the meta document that
	 * matches the vector id. The meta documents are queried in bulk up to a maximum number.
	 * Two iterators pointing to the same list of VectorResults must be supplied. One is
	 * used to generate the bulk query document. The second is used to fill in the hitcount
	 * field from the resulting meta documents. If no exception is thrown, both iterators
	 * will be advanced the same number of times.
	 * @param iter1 is the iterator to VectorResults to fill in
	 * @param iter2 is a copy of the first iterator
	 * @param maxDocuments is the maximum number of documents to query for
	 * @return the total number of function matching the vectors queried
	 * @throws ElasticException for communication problems with the server
	 */
	private long fetchVectorCounts(Iterator<VectorResult> iter1, Iterator<VectorResult> iter2,
			int maxDocuments) throws ElasticException {
		if (!iter1.hasNext()) {
			return 0;
		}
		long totalCount = 0;
		VectorResult vecRes = iter1.next();
		StringBuilder buffer = new StringBuilder();
		// append the first id
		buffer.append("{ \"ids\": [ ");
		buffer.append('\"');
		Base64Lite.encodeLongBase64(buffer, vecRes.vectorid);
		buffer.append('\"');
		for (int i = 1; i < maxDocuments; ++i) {
			if (!iter1.hasNext()) {
				break;
			}
			vecRes = iter1.next();
			buffer.append(", \"");
			Base64Lite.encodeLongBase64(buffer, vecRes.vectorid);
			buffer.append('\"');
		}
		buffer.append(" ] }");
		JSONObject resp =
			connection.executeStatement(ElasticConnection.GET, "meta/_mget", buffer.toString());
		JSONArray docs = (JSONArray) resp.get("docs");
		for (int i = 0; i < maxDocuments; ++i) {
			if (!iter2.hasNext()) {
				break;
			}
			vecRes = iter2.next();
			JSONObject oneResp = (JSONObject) docs.get(i);
			String matchId = (String) oneResp.get("_id");
			long matchIdVal = Base64Lite.decodeLongBase64(matchId);
			JSONObject source = (JSONObject) oneResp.get("_source");
			if (source == null) {
				throw new ElasticException("meta document does not exist for id=" + matchId);
			}
			if (matchIdVal != vecRes.vectorid) {
				throw new ElasticException("Mismatch in metaid");
			}
			long count = (Long) source.get("count");
			totalCount += count;
			vecRes.hitcount = (int) count;
		}
		return totalCount;
	}

	/**
	 * Fetch vectors in bulk from the database, given a list of VectorResults with the vector ids
	 * The vector documents are queried, then the resulting LSHVector objects are filled
	 * in for the VectorResults by parsing the documents. Two iterators pointing to the same list
	 * of VectorResults are required, one for building the query, one for filling in the LSHVectors.
	 * If no exception is thrown, both iterators are advanced the same number of times.
	 * @param iter1 is the iterator to VectorResults to fill in
	 * @param iter2 is a copy of the first iterator
	 * @param maxDocuments is the maximum number of documents to query for
	 * @throws ElasticException for communication problems with the server
	 */
	private void fetchVectors(Iterator<VectorResult> iter1, Iterator<VectorResult> iter2,
			int maxDocuments) throws ElasticException {
		if (!iter1.hasNext()) {
			return;
		}
		VectorResult vecRes = iter1.next();
		StringBuilder buffer = new StringBuilder();
		// append the first id
		buffer.append("{ \"ids\": [ ");
		buffer.append('\"');
		Base64Lite.encodeLongBase64(buffer, vecRes.vectorid);
		buffer.append('\"');
		for (int i = 1; i < maxDocuments; ++i) {
			if (!iter1.hasNext()) {
				break;
			}
			vecRes = iter1.next();
			buffer.append(", \"");
			Base64Lite.encodeLongBase64(buffer, vecRes.vectorid);
			buffer.append('\"');
		}
		buffer.append(" ] }");
		JSONObject resp =
			connection.executeStatement(ElasticConnection.GET, "vector/_mget", buffer.toString());
		JSONArray docs = (JSONArray) resp.get("docs");
		char[] vectorDecodeBuffer = Base64VectorFactory.allocateBuffer();
		for (int i = 0; i < maxDocuments; ++i) {
			if (!iter2.hasNext()) {
				break;
			}
			vecRes = iter2.next();
			JSONObject oneResp = (JSONObject) docs.get(i);
			String matchId = (String) oneResp.get("_id");
			long matchIdVal = Base64Lite.decodeLongBase64(matchId);
			JSONObject source = (JSONObject) oneResp.get("_source");
			if (source == null) {
				throw new ElasticException("vector document does not exist for id=" + matchId);
			}
			if (matchIdVal != vecRes.vectorid) {
				throw new ElasticException("Mismatch in vectorid");
			}
			StringReader reader = new StringReader((String) source.get("features"));
			try {
				vecRes.vec = vectorFactory.restoreVectorFromBase64(reader, vectorDecodeBuffer);
			}
			catch (IOException e) {
				throw new ElasticException(e.getMessage());
			}
		}
	}

	/**
	 * Given a list of FunctionDescriptions, fill in the matching SignatureRecords
	 * @param listFunctions is the list of functions
	 * @param manager is the FunctionDescription container
	 * @throws ElasticException for communication problems with the server
	 */
	private void queryAssociatedSignatures(List<FunctionDescription> listFunctions,
			DescriptionManager manager) throws ElasticException {
		TreeMap<Long, VectorResult> vecMap = new TreeMap<>();
		for (FunctionDescription fdesc : listFunctions) {				// Collect (unique) vectorids across FunctionDescriptions
			if (fdesc.getSignatureRecord() != null) {
				continue;
			}
			Long key = Long.valueOf(fdesc.getVectorId());
			if (vecMap.containsKey(key)) {
				continue;
			}
			VectorResult vecRes = new VectorResult();
			vecRes.vectorid = key.longValue();
			vecMap.put(key, vecRes);
		}
		Iterator<VectorResult> iter1 = vecMap.values().iterator();
		Iterator<VectorResult> iter2 = vecMap.values().iterator();
		while (iter1.hasNext()) {
			fetchVectors(iter1, iter2, 50);						// Fetch vector associated with each vectorid
		}
		iter1 = vecMap.values().iterator();
		iter2 = vecMap.values().iterator();
		while (iter1.hasNext()) {
			fetchVectorCounts(iter1, iter2, MAX_VECTORCOUNT_WINDOW);	// Fetch hitcount of each vector
		}
		TreeMap<Long, SignatureRecord> sigMap = new TreeMap<>();
		for (Entry<Long, VectorResult> entry : vecMap.entrySet()) {		// Build SignatureRecord for each (id,vector,hitcount)
			SignatureRecord sigRec =
				manager.newSignature(entry.getValue().vec, entry.getValue().hitcount);
			manager.setSignatureId(sigRec, entry.getKey());
			sigMap.put(entry.getKey(), sigRec);
		}
		for (FunctionDescription fdesc : listFunctions) {						// Attach SignatureRecords to FunctionDescriptions
			if (fdesc.getSignatureRecord() != null) {
				continue;
			}
			SignatureRecord sigRec = sigMap.get(fdesc.getVectorId());
			manager.attachSignature(fdesc, sigRec);
		}
	}

	/**
	 * Query for function documents that match a given vector id and
	 * passes additional filters. The filter must already be encoded as a JSON fragment.
	 * @param vectorId is the vector id to match
	 * @param filter is the JSON fragment describing the filter
	 * @param maxDocuments is the maximum number of documents to return
	 * @return list of matching functions as JSON documents
	 * @throws ElasticException for communication problems with the server
	 */
	private JSONArray queryVectorIdMatch(long vectorId, String filter, int maxDocuments)
			throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"size\": ").append(maxDocuments);
		buffer.append(", \"_source\": { \"excludes\": [ \"childid\" ] }");
		buffer.append(", \"query\": { ");
		buffer.append("    \"bool\": { ");
		buffer.append("      \"must\": { ");
		buffer.append("        \"term\": { \"id_signature\": \"");
		Base64Lite.encodeLongBase64(buffer, vectorId);
		buffer.append("\" } }");
		if (filter != null) {
			buffer.append(filter);
		}
		buffer.append("} } }");
		JSONObject resp = connection.executeStatement(ElasticConnection.GET, "executable/_search",
			buffer.toString());
		JSONObject baseHits = (JSONObject) resp.get("hits");
		JSONObject totalRec = (JSONObject) baseHits.get("total");
		long total = (Long) totalRec.get("value");
		if (total == 0) {
			return new JSONArray();
		}
		JSONArray hitsArray = (JSONArray) baseHits.get("hits");
		return hitsArray;
	}

	/**
	 * Query the database for all vectors that are "near" a given vector in terms
	 * of similarity and significance. The routine returns a list of VectorResult
	 * objects with the id, LSHVector, and hitcount filled in.
	 * @param listResult is the discovered list of VectorResults
	 * @param vector is the vector being queried
	 * @param similarityThreshold is the similarity threshold results must exceed
	 * @param significanceThreshold is the significance threshold results must exceed
	 * @param maxVectors is the maximum number of (distinct) vectors to return
	 * @return the total number of functions matching one of the returned vectors
	 * @throws ElasticException for communication problems with the server
	 */
	private long queryNearestVector(List<VectorResult> listResult, LSHVector vector,
			double similarityThreshold, double significanceThreshold, int maxVectors)
			throws ElasticException {
		if (connection == null) {
			return 0;
		}
		StringBuilder vecEncode = new StringBuilder();
		vector.saveBase64(vecEncode, Base64Lite.encode);
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"size\": ").append(maxVectors).append(", ");
		buffer.append("  \"query\": { ");
		buffer.append("  \"function_score\": { ");
		buffer.append("    \"query\": { ");
		buffer.append("      \"match\": { ");
		buffer.append("        \"features\": \"");
		buffer.append(vecEncode);
		buffer.append("\" } }, ");
		buffer.append("    \"min_score\": 0.00001, ");		// Make sure a 0.0 score is filtered
		buffer.append("    \"boost_mode\": \"replace\", ");
		buffer.append("    \"functions\": [ { ");
		buffer.append("      \"script_score\": { ");
		buffer.append("        \"script\": { ");
		buffer.append("          \"lang\": \"bsim_scripts\", ");
		buffer.append("          \"source\": \"lsh_compare\", ");
		buffer.append("          \"params\": { ");
		buffer.append("            \"indexname\": \"lsh_").append(repository).append("\", ");
		buffer.append("            \"vector\": \"");
		buffer.append(vecEncode);
		buffer.append("\",          \"simthresh\": ").append(similarityThreshold);
		buffer.append(",            \"sigthresh\": ").append(significanceThreshold);
		buffer.append(" } } } } ] } } }");
		JSONObject resp =
			connection.executeStatement(ElasticConnection.GET, "vector/_search", buffer.toString());
		JSONObject baseHits = (JSONObject) resp.get("hits");
		if (baseHits == null) {
			throw new ElasticException("Could not find hits document");
		}
		JSONObject totalRec = (JSONObject) baseHits.get("total");
		long numHits = (Long) totalRec.get("value");
		if (numHits == 0) {
			return 0;
		}
		JSONArray hitsArray = (JSONArray) baseHits.get("hits");
		char[] decodeBuffer = Base64VectorFactory.allocateBuffer();
		VectorCompare vecCompare = new VectorCompare();
		try {
			int returnedHits = hitsArray.size();
			for (int i = 0; i < returnedHits; ++i) {
				JSONObject mainHit = (JSONObject) hitsArray.get(i);
				VectorResult vecRes = new VectorResult();
				vecRes.vectorid = Base64Lite.decodeLongBase64((String) mainHit.get("_id"));
				vecRes.hitcount = -1;		// Cannot fill in at this time
				vecRes.sim = (Double) mainHit.get("_score");
				JSONObject source = (JSONObject) mainHit.get("_source");
				StringReader reader = new StringReader((String) source.get("features"));
				vecRes.vec = vectorFactory.restoreVectorFromBase64(reader, decodeBuffer);
				vector.compareCounts(vecRes.vec, vecCompare);
				vecCompare.dotproduct = vecRes.sim * vector.getLength() * vecRes.vec.getLength();
				vecRes.signif = vectorFactory.calculateSignificance(vecCompare);
				listResult.add(vecRes);
			}
		}
		catch (IOException ex) {
			throw new ElasticException("Bad encoding in result document");
		}
		long totalCount = 0;
		Iterator<VectorResult> iter1 = listResult.iterator();
		Iterator<VectorResult> iter2 = listResult.iterator();
		while (iter1.hasNext()) {
			totalCount += fetchVectorCounts(iter1, iter2, MAX_VECTORCOUNT_WINDOW);
		}
		return totalCount;
	}

	/**
	 * Returns the total number of hits in the given list of VectorResults
	 * 
	 * @param listResult is the list of VectorResults
	 * @return the total count
	 */
	private int getTotalCount(List<VectorResult> listResult) {
		int count = 0;
		for (VectorResult res : listResult) {
			count += res.hitcount;
		}
		return count;
	}

	/**
	 * Query the database for functions that are similar to the given feature vector
	 * @param similarityResult receives the list of results and their similarity to the base vector
	 * @param manager is the DescriptionManager container for the results
	 * @param vector is the feature vector to match
	 * @param query contains various thresholds for the query
	 * @param filter specifies additional conditions functions (and exes) must meet after meeting sim/signif threshold
	 * @param vecToResultsMap is a cache of VectorResult lists from previous queries
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems adding new records to the container
	 */
	private void queryNearest(SimilarityResult similarityResult, DescriptionManager manager,
			LSHVector vector, QueryNearest query, String filter,
			HashMap<LSHVector, List<VectorResult>> vecToResultsMap)
			throws ElasticException, LSHException {
		List<VectorResult> resultset = new ArrayList<>();
		int vectormax = query.vectormax;
		if (vectormax == 0) {
			vectormax = MAX_VECTOR_OVERALL; // Really means a very big limit
		}

		// Check to see if we've already queried for this vector before. If so, just grab
		// the results from the map.
		if (vecToResultsMap.containsKey(vector)) {
			resultset = vecToResultsMap.get(vector);
			similarityResult.setTotalCount(getTotalCount(resultset));
		}
		else {
			// Perform the query.
			similarityResult.setTotalCount((int) queryNearestVector(resultset, vector, query.thresh,
				query.signifthresh, vectormax));

			// Put the new results in the map so we can use them if another 
			// similar vector comes along.
			vecToResultsMap.put(vector, resultset);
		}

		int count = 0;

		for (VectorResult dresult : resultset) {
			if (count >= query.max) {
				break;
			}
			final SignatureRecord srec = manager.newSignature(dresult.vec, dresult.hitcount);
			JSONArray descres;
			descres = queryVectorIdMatch(dresult.vectorid, filter, query.max - count);
			if (descres == null) {
				throw new ElasticException(
					"Error querying vectorid: " + Long.toString(dresult.vectorid));
			}
			if (descres.size() == 0) {
				if (filter != null) {
					continue; // Filter may have eliminated all results
				}
				// Otherwise this is a sign of corruption in the database
				throw new ElasticException(
					"No functions matching vectorid: " + Long.toString(dresult.vectorid));
			}
			count += descres.size();
			convertDescriptionRows(similarityResult, descres, dresult, manager, srec);
		}
	}

	/**
	 * Perform a full QueryNearest request, with additional filters, placing SimilarityResults
	 * in the ResponseNearest object. An iterator to FunctionDescriptions determines what
	 * subset of functions are actually being queried.
	 * @param query is overarching QueryNearest object
	 * @param filter is the (optional) additional filters results must pass
	 * @param response is the ResponseNearest accumulating results
	 * @param manager is an internal placeholder container primarily for caching ExecutableRecords 
	 * @param iter points to the subset of functions to query
	 * @return the total number of unique result sets produced by the query
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems adding new records to the response
	 */
	private int queryFunctions(QueryNearest query, String filter, ResponseNearest response,
			DescriptionManager manager, Iterator<FunctionDescription> iter)
			throws ElasticException, LSHException {

		// Keep a map of the feature vectors and their query results; if we have vectors that
		// are of equal value, we'll just query the first one, and use those results for the
		// others.
		HashMap<LSHVector, List<VectorResult>> vecToResultMap = new HashMap<>();

		while (iter.hasNext()) {
			final FunctionDescription frec = iter.next();
			final SignatureRecord srec = frec.getSignatureRecord();

			if (srec == null) {
				continue;
			}
			final LSHVector thevec = srec.getLSHVector();
			final double len2 = vectorFactory.getSelfSignificance(thevec);

			// Self significance should be bigger than the significance threshold
			// (or its impossible our result can exceed the threshold)
			if (len2 < query.signifthresh) {
				continue;
			}
			response.totalfunc += 1;
			final SimilarityResult simres = new SimilarityResult(frec);
			if (manager.getExecutableRecordSet().size() > 1000) {
				manager.clear();
			}
			else {
				// Try to preserve ExecutableRecords so we don't have to connect every time 
				manager.clearFunctions();
			}
			queryNearest(simres, manager, thevec, query, filter, vecToResultMap);
			if (simres.size() == 0) {
				continue;
			}
			response.totalmatch += 1;
			if (simres.size() == 1) {
				response.uniquematch += 1;
			}

			response.result.add(simres);

			simres.transfer(response.manage, true);
		}

		return vecToResultMap.size();
	}

	/**
	 * Query for function names within a previously queried executable
	 * @param listFunctions - list of functions to be filled in by the query (may be null)
	 * @param manager - container for record
	 * @param exeRecord - previously queried ExecutableRecord
	 * @param functionName - name to query for, if empty string, all functions in executable are returned
	 * @param fillInSignatures - true if SignatureRecords should be filled in for resulting FunctionDescriptions
	 * @param maxFunctions - maximum results to return
	 * @throws ElasticException for communication problems with the server
	 */
	private void queryByName(List<FunctionDescription> listFunctions, DescriptionManager manager,
			ExecutableRecord exeRecord, String functionName, boolean fillInSignatures,
			int maxFunctions) throws ElasticException {
		RowKeyElastic eKey = (RowKeyElastic) exeRecord.getRowId();
		String exeId = eKey.generateExeIdString();
		if (listFunctions == null) {
			listFunctions = new ArrayList<>();
		}
		if (functionName.length() == 0) {
			queryAllFunc(listFunctions, exeRecord, exeId, manager, maxFunctions);
		}
		else {
			JSONArray hitsarray = queryFuncNameMatch(exeId, functionName, maxFunctions);
			JSONObject doc = null;
			for (Object element : hitsarray) {
				doc = (JSONObject) element;
				FunctionDescription funcDesc = convertDescriptionRow(doc, exeRecord, manager, null);
				listFunctions.add(funcDesc);
			}
		}
		if (fillInSignatures) {
			queryAssociatedSignatures(listFunctions, manager);
		}
	}

	/**
	 * Given an ExecutableRecord, function name, and address, query for
	 * the matching FunctionDescription.
	 * @param manager is the container for the FunctionDescription
	 * @param exeRecord is the given executable
	 * @param functionName is the function name
	 * @param address is the function address
	 * @param fillInSignatures is true if the SignatureRecord should be filled in
	 * @return the recovered FunctionDescription or null if not found
	 * @throws ElasticException for communication problems with the server
	 */
	private FunctionDescription queryByNameAddress(DescriptionManager manager,
			ExecutableRecord exeRecord, String functionName, long address, boolean fillInSignatures)
			throws ElasticException {
		RowKeyElastic eKey = (RowKeyElastic) exeRecord.getRowId();
		String exeId = eKey.generateExeIdString();
		JSONObject doc = queryFuncNameAddress(exeId, functionName, address);
		if (doc == null) {
			return null;
		}
		FunctionDescription funcDesc = convertDescriptionRow(doc, exeRecord, manager, null);
		if (fillInSignatures) {
			List<FunctionDescription> vecres = new ArrayList<>();
			vecres.add(funcDesc);
			queryAssociatedSignatures(vecres, manager);
		}
		return funcDesc;
	}

	/**
	 * Retrieve a sequence of ExecutableRecords by id. The ids are queried in bulk,
	 * up to a given maximum number of documents to fetch. Two iterators pointing to
	 * the same list of RowKeys must be provided.  One is used while building the query
	 * document. The other is used to assign the matching RowKey to the new ExecutableRecords
	 * @param manager is the container to store new ExecutableRecord results
	 * @param iter1 is an iterator over ids
	 * @param iter2 is a copy of the iterator over ids
	 * @param maxDocuments is the maximum number of ids to fetch in this request
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems adding new records to the container
	 */
	private void queryExecutableRecordById(DescriptionManager manager,
			Iterator<RowKeyElastic> iter1, Iterator<RowKeyElastic> iter2, int maxDocuments)
			throws ElasticException, LSHException {
		StringBuilder buffer = new StringBuilder();
		if (!iter1.hasNext()) {
			return;		// Nothing to do
		}
		String path = '/' + repository + "_executable/_msearch";
		int count = 0;
		for (int i = 0; i < maxDocuments; ++i) {
			String exeId = iter1.next().generateExeIdString();
			buffer.append("{}\n");		// Keep default index and type
			buffer.append("{ \"query\": { \"bool\": { \"filter\": { \"term\": { \"_id\": \"");
			buffer.append(exeId);
			buffer.append("\" }}}}}\n");
			count += 1;
			if (!iter1.hasNext()) {
				break;
			}
		}
		JSONObject bulkobj = connection.executeBulk(path, buffer.toString());
		JSONArray responses = (JSONArray) bulkobj.get("responses");
		for (int i = 0; i < count; ++i) {
			JSONObject subquery = (JSONObject) responses.get(i);
			JSONObject hits = (JSONObject) subquery.get("hits");
			if (hits == null) {
				throw new ElasticException("Multi-search for exe records failed");
			}
			JSONObject totalRec = (JSONObject) hits.get("total");
			long total = (Long) totalRec.get("value");
			if (total != 1) {
				throw new ElasticException("Could not recover unique executable via id");
			}
		}
		for (int i = 0; i < count; ++i) {
			JSONObject subquery = (JSONObject) responses.get(i);
			JSONObject hits = (JSONObject) subquery.get("hits");
			JSONArray hitsArray = (JSONArray) hits.get("hits");
			hits = (JSONObject) hitsArray.get(0);
			ExecutableRecord newExe = makeExecutableRecord(manager, hits);
			RowKey rowKey = iter2.next();
			manager.cacheExecutableByRow(newExe, rowKey);
		}
	}

	/**
	 * Query for function documents based on their parent executable id.
	 * A "page" of results is selected by selecting a -start- document and a maximum number to return
	 * @param exeId is the executable id
	 * @param maxDocuments is the maximum number of functions to return
	 * @param start is the number functions to skip
	 * @return the JSON response object
	 * @throws ElasticException for communication problems with the server
	 */
	private JSONObject queryFunctionsOfExeId(String exeId, long maxDocuments, long start)
			throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"size\": ").append(maxDocuments);
		buffer.append(", \"_source\": { \"excludes\": [ \"childid\" ] }");
		buffer.append(", \"query\": { \"parent_id\": { \"type\": \"function\", \"id\": \"")
				.append(exeId)
				.append("\" }}");
		if (start != 0) {
			buffer.append(", \"search_after\": [").append(start).append(']');
		}
		buffer.append(", \"sort\": [ { \"_doc\": \"asc\" } ] }");
		return connection.executeStatement(ElasticConnection.GET, "executable/_search",
			buffer.toString());
	}

	/**
	 * Query for all functions (up to a maximum) of the given executable.
	 * Populate a list with the resulting FunctionDescription objects
	 * Does NOT populate SignatureRecord or CallGraph parts of the FunctionDescription
	 * @param listFunctions has all queried functions added to it
	 * @param exeRecord is the executable containing the functions
	 * @param exeId is a precomputed document id of the executable
	 * @param manager is the container for the new records
	 * @param maxDocuments is the maximum number of records to read
	 * @return the number of function records read
	 * @throws ElasticException for communication problems with the server
	 */
	private int queryAllFunc(List<FunctionDescription> listFunctions, ExecutableRecord exeRecord,
			String exeId, DescriptionManager manager, int maxDocuments) throws ElasticException {
		long total;
		long start = 0;
		do {
			int limit = MAX_FUNCTION_WINDOW;
			if (maxDocuments != 0 && maxDocuments - start < limit) {
				limit = (int) (maxDocuments - start);
			}
			JSONObject resp = queryFunctionsOfExeId(exeId, limit, start);
			JSONObject hits = (JSONObject) resp.get("hits");
			JSONObject totalRec = (JSONObject) hits.get("total");
			total = (Long) totalRec.get("value");
			if (maxDocuments != 0 && maxDocuments < total) {
				total = maxDocuments;
			}
			JSONArray hitsarray = (JSONArray) hits.get("hits");
			JSONObject doc = null;
			for (Object element : hitsarray) {
				doc = (JSONObject) element;
				FunctionDescription funcDesc = convertDescriptionRow(doc, exeRecord, manager, null);
				listFunctions.add(funcDesc);
			}
			if (hitsarray.size() == 0) {
				break;			// Shouldn't need this, but just in case
			}
			JSONArray sort = (JSONArray) doc.get("sort");
			start = (Long) sort.get(0);					// Sort value for last entry, for passing as search_after parameter			
		}
		while (total > start);
		return (int) total;
	}

	/**
	 * Issue a bulk update request to the database, given a list of update records
	 * for functions from a single executable.
	 * The routine needs an iterator to the FunctionDescription.Updates and only processes up to
	 * a given maximum number in the one bulk request.
	 * @param iter is the iterator to the update records
	 * @param exeId is the document id of the executable containing the functions
	 * @param maxFunctions is the maximum number of updates to put in the one request
	 * @throws ElasticException for communication problems with the server
	 */
	private void updateFunctions(Iterator<FunctionDescription.Update> iter, String exeId,
			int maxFunctions) throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		do {
			FunctionDescription.Update rec = iter.next();
			RowKeyElastic eKey = (RowKeyElastic) rec.update.getExecutableRecord().getRowId();
			buffer.append("{ \"update\": { \"_index\": \"")
					.append(repository)
					.append("_executable\", ");
			buffer.append("\"_id\": \"");
			eKey.generateFunctionId(buffer, rec.update);
			buffer.append("\", \"routing\": \"").append(exeId).append("\"} }\n");
			buffer.append("{ \"doc\": { ");
			boolean needscomma = false;
			if (rec.function_name) {
				needscomma = true;
				buffer.append("\"name_func\": \"")
						.append(JSONObject.escape(rec.update.getFunctionName()))
						.append('\"');
			}
			if (rec.flags) {
				if (needscomma) {
					buffer.append(',');
				}
				buffer.append(" \"flags\": ").append(rec.update.getFlags());
			}
			buffer.append("} }\n");
		}
		while (iter.hasNext());
		connection.executeBulk("/_bulk", buffer.toString());
	}

	/**
	 * Issue an update request for single executable, given its document id and an update record
	 * @param updateRecord is the executable specific update record
	 * @param exeId is the document id of the executable
	 * @throws ElasticException for communication problems with the server
	 */
	private void updateExecutable(ExecutableRecord.Update updateRecord, String exeId)
			throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		boolean needscomma = false;
		buffer.append("{ \"doc\": {");
		if (updateRecord.name_exec) {
			needscomma = true;
			buffer.append("\"name_exec\": \"")
					.append(JSONObject.escape(updateRecord.update.getNameExec()))
					.append('\"');
		}
		if (updateRecord.architecture) {
			if (needscomma) {
				buffer.append(',');
			}
			else {
				needscomma = true;
			}
			buffer.append("\"architecture\": \"")
					.append(updateRecord.update.getArchitecture())
					.append('\"');
		}
		if (updateRecord.name_compiler) {
			if (needscomma) {
				buffer.append(',');
			}
			else {
				needscomma = true;
			}
			buffer.append("\"name_compiler\": \"")
					.append(updateRecord.update.getArchitecture())
					.append('\"');
		}
		if (updateRecord.date) {
			if (needscomma) {
				buffer.append(',');
			}
			else {
				needscomma = true;
			}
			buffer.append("\"ingest_date\": ").append(updateRecord.update.getDate().getTime());
		}
		if (updateRecord.repository) {
			if (needscomma) {
				buffer.append(',');
			}
			else {
				needscomma = true;
			}
			buffer.append("\"repository\": \"")
					.append(updateRecord.update.getRepository())
					.append('\"');
		}
		if (updateRecord.path) {
			if (needscomma) {
				buffer.append(',');
			}
			else {
				needscomma = true;
			}
			buffer.append("\"path\": \"").append(updateRecord.update.getPath()).append('\"');
		}
		if (updateRecord.categories) {
			if (needscomma) {
				buffer.append(',');
			}
			else {
				needscomma = true;
			}
			appendCategoryTag(updateRecord.update.getAllCategories(), buffer);
		}
		buffer.append("} }");
		StringBuilder pathBuffer = new StringBuilder();
		pathBuffer.append("executable/_update/");
		pathBuffer.append(exeId);
		connection.executeStatementNoResponse(ElasticConnection.POST, pathBuffer.toString(),
			buffer.toString());
	}

	/**
	 * Update metadata for the executable -erec- and all its functions (in manager)
	 * @param manager is the collection of functions to update
	 * @param exeRecord is the root executable
	 * @param badFunctions collects references to functions with update info that could not be identified
	 * @return -1 if the executable could not be found, otherwise return 2*# of
	 *         update functions + 1 if the executable metadata is also updated
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems grouping records
	 */
	private int updateExecutable(DescriptionManager manager, ExecutableRecord exeRecord,
			List<FunctionDescription> badFunctions) throws ElasticException, LSHException {
		JSONObject row = queryMd5ExeMatch(exeRecord.getMd5());
		if (row == null) {
			return -1; // Indicate that we couldn't find the executable
		}
		ExecutableRecord erec_db = makeExecutableRecordTemp(row);
		DescriptionManager dbmanage = new DescriptionManager();
		erec_db = dbmanage.transferExecutable(erec_db);
		ExecutableRecord.Update exe_update = new ExecutableRecord.Update();
		boolean has_exe_update = exeRecord.diffForUpdate(exe_update, erec_db);

		// Load all the functions in the database under this executable
		RowKeyElastic eKey = (RowKeyElastic) erec_db.getRowId();
		String exeId = eKey.generateExeIdString();
		List<FunctionDescription> funclist = new ArrayList<>();
		queryAllFunc(funclist, erec_db, exeId, dbmanage, 0);

		// Create a map from address to executables
		Map<Long, FunctionDescription> addrmap =
			FunctionDescription.createAddressToFunctionMap(funclist.iterator());

		// Match new functions to old functions via the address
		List<FunctionDescription.Update> updatelist;
		updatelist = FunctionDescription.generateUpdates(manager.listFunctions(exeRecord), addrmap,
			badFunctions);

		if (!has_exe_update && updatelist.isEmpty()) {
			return 0; // All updates are in place already
		}

		// Do the actual database updates
		if (has_exe_update) {
			updateExecutable(exe_update, exeId);
		}
		Iterator<FunctionDescription.Update> iter = updatelist.iterator();
		while (iter.hasNext()) {
			updateFunctions(iter, exeId, MAX_FUNCTIONUPDATE_WINDOW);
		}
		int val = has_exe_update ? 1 : 0;
		val += 2 * updatelist.size();
		return val;
	}

	/**
	 * Create a list of CategoryRecord objects from an "exe" JSON document,
	 * by extracting all the "execategory" properties from the document
	 * @param source is the exe document
	 * @return the list of CategoryRecords
	 */
	private static List<CategoryRecord> makeCategoryList(JSONObject source) {
		JSONArray catArray = (JSONArray) source.get("execategory");
		if (catArray == null || catArray.size() == 0) {
			return null;
		}
		List<CategoryRecord> res = new ArrayList<>();
		for (Object element : catArray) {
			String concat = (String) element;
			int pos = concat.indexOf('\t');
			if (pos > 0) {
				String type = concat.substring(0, pos);
				String value = concat.substring(pos + 1);
				res.add(new CategoryRecord(type, value));
			}
		}
		return res;
	}

	/**
	 * Create an ExecutableRecord from a JSON "hit" document returned when querying the executable/exe index
	 * The record will not be attached to any container (DescriptionManager), although it
	 * can be transferred into a container later.
	 * @param hit is the "hit" document, which should have an "_id" and "_source" property.
	 * @return the new ExecutableRecord parsed from the document
	 */
	private static ExecutableRecord makeExecutableRecordTemp(JSONObject hit) {
		RowKeyElastic eKey = RowKeyElastic.parseExeIdString((String) hit.get("_id"));
		JSONObject source = (JSONObject) hit.get("_source");
		String md5 = (String) source.get("md5");
		String exename = (String) source.get("name_exec");
		String arch = (String) source.get("architecture");
		ExecutableRecord exeres;
		if (ExecutableRecord.isLibraryHash(md5)) {
			exeres = new ExecutableRecord(exename, arch, eKey);
		}
		else {
			String cname = (String) source.get("name_compiler");
			String repo = (String) source.get("repository");
			String path = null;
			if (repo != null) {
				path = (String) source.get("path");
			}
			List<CategoryRecord> catrecs = makeCategoryList(source);
			long milli = (Long) source.get("ingest_date");
			exeres = new ExecutableRecord(md5, exename, cname, arch, new Date(milli), catrecs, eKey,
				repo, path);
		}
		return exeres;
	}

	/**
	 * Create an ExecutableRecord from a JSON "hit" document returned when querying the executable/exe index
	 * @param manager is the container that will own the new record
	 * @param hit is the "hit" document, which should have an "_id" and "_source" property.
	 * @return the new ExecutableRecord parsed from the document
	 * @throws LSHException if the container already contains executable with different metadata
	 */
	private static ExecutableRecord makeExecutableRecord(DescriptionManager manager, JSONObject hit)
			throws LSHException {
		RowKeyElastic eKey = RowKeyElastic.parseExeIdString((String) hit.get("_id"));
		JSONObject source = (JSONObject) hit.get("_source");
		String md5 = (String) source.get("md5");
		String exename = (String) source.get("name_exec");
		String arch = (String) source.get("architecture");

		ExecutableRecord exerec;
		if (ExecutableRecord.isLibraryHash(md5)) {
			exerec = manager.newExecutableLibrary(exename, arch, eKey);
		}
		else {
			String cname = (String) source.get("name_compiler");
			String repo = (String) source.get("repository");
			String path = null;
			if (repo != null) {
				path = (String) source.get("path");
			}
			List<CategoryRecord> catrecs = makeCategoryList(source);
			long milli = (Long) source.get("ingest_date");
			Date date = new Date(milli);
			exerec = manager.newExecutableRecord(md5, exename, cname, arch, date, repo, path, eKey);
			if (catrecs != null) {
				manager.setExeCategories(exerec, catrecs);
			}
		}
		return exerec;
	}

	/**
	 * Build a FunctionDescription object in -manager- container from a -hit- document
	 * returned from a query into the executable/function index.
	 * @param hit the hit document
	 * @param exeRecord is the executable containing this function
	 * @param manager is the DescriptionManager container
	 * @param sigRecord is the (optional) SignatureRecord to attach to the new function
	 * @return the new FunctionDescription
	 */
	private static FunctionDescription convertDescriptionRow(JSONObject hit,
			ExecutableRecord exeRecord, DescriptionManager manager, SignatureRecord sigRecord) {
		RowKey rowid = RowKeyElastic.parseFunctionId((String) hit.get("_id"));
		JSONObject source = (JSONObject) hit.get("_source");
		String func_name = (String) source.get("name_func");
		long addr = (Long) source.get("addr");
		int flags = ((Long) source.get("flags")).intValue();
		long id_sig = Base64Lite.decodeLongBase64((String) source.get("id_signature"));
		FunctionDescription fres = manager.newFunctionDescription(func_name, addr, exeRecord);
		manager.setFunctionDescriptionId(fres, rowid);
		manager.setFunctionDescriptionFlags(fres, flags);
		manager.setSignatureId(fres, id_sig);
		if (sigRecord != null) {
			manager.setSignatureId(sigRecord, id_sig);
			manager.attachSignature(fres, sigRecord);
		}
		return fres;
	}

	/**
	 * Convert function documents, presented as an array of JSON objects, that all
	 * share a single feature vector returned by a nearest neighbor query, into
	 * FunctionDescriptions and a full SimilarityResult.
	 * Each function document will be parsed into a FunctionDescription,
	 * and a SimilarityNote will be created describing its similarity to
	 * the query vector based on the raw VectorResult data.
	 * @param similarityResult is the container for the SimilarityNotes
	 * @param descRows is the array of JSON function documents
	 * @param vectorResult is the raw vector query result
	 * @param manager is the container for new FunctionDescriptions
	 * @param sigRecord is the shared feature vector
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems adding new records to the container
	 */
	protected void convertDescriptionRows(SimilarityResult similarityResult, JSONArray descRows,
			VectorResult vectorResult, DescriptionManager manager, SignatureRecord sigRecord)
			throws ElasticException, LSHException {
		if (descRows.size() == 0) {
			return;
		}
		List<RowKeyElastic> parentIds = new ArrayList<>(descRows.size());
		Set<RowKeyElastic> parents = new TreeSet<>();
		RowKeyElastic eKey;
		String exeid;
		for (Object descRow : descRows) {
			JSONObject hit = (JSONObject) descRow;
			JSONObject source = (JSONObject) hit.get("_source");
			JSONObject joinfield = (JSONObject) source.get("join_field");
			exeid = (String) joinfield.get("parent");
			eKey = RowKeyElastic.parseExeIdString(exeid);
			parentIds.add(eKey);
			if (manager.findExecutableByRow(eKey) == null) {
				parents.add(eKey);
			}
		}
		Iterator<RowKeyElastic> iter1 = parents.iterator();
		Iterator<RowKeyElastic> iter2 = parents.iterator();
		while (iter1.hasNext()) {
			queryExecutableRecordById(manager, iter1, iter2, 100);
		}

		JSONObject currow = (JSONObject) descRows.get(0);
		eKey = parentIds.get(0);
		ExecutableRecord curexe = manager.findExecutableByRow(eKey);
		FunctionDescription fres = convertDescriptionRow(currow, curexe, manager, sigRecord);
		if (similarityResult != null) {
			similarityResult.addNote(fres, vectorResult.sim, vectorResult.signif);
		}
		for (int i = 1; i < descRows.size(); ++i) {
			currow = (JSONObject) descRows.get(i);
			eKey = parentIds.get(i);
			curexe = manager.findExecutableByRow(eKey);
			fres = convertDescriptionRow(currow, curexe, manager, sigRecord);
			if (similarityResult != null) {
				similarityResult.addNote(fres, vectorResult.sim, vectorResult.signif);
			}
		}
	}

	/**
	 * Insert a library executable and all the functions it contains into the database.
	 * The executable must be a library. The routine will complete successfully even if
	 * the executable or some of its functions have been inserted before.
	 * @param manager is container of the executable
	 * @param exeRecord is the ExecutableRecord describing the library
	 * @throws ElasticException for communication problems with the server
	 */
	private void insertLibrary(DescriptionManager manager, ExecutableRecord exeRecord)
			throws ElasticException {
		RowKeyElastic eKey = updateKey(manager, exeRecord);
		String exeId = eKey.generateExeIdString();
		insertExecutableRecord(exeRecord, exeId);		// May or may not already be inserted, doesn't matter

		Iterator<FunctionDescription> iter = manager.listFunctions(exeRecord);
		while (iter.hasNext()) {
			insertFunctionRange(manager, exeRecord, eKey, exeId, iter, MAX_FUNCTION_BULK);		// Insert functions some of which may already be inserted
		}
	}

	/**
	 * Insert an executable and all of the functions it contains into the database.
	 * The executable must not be a library.  If the executable has been inserted before,
	 * a non-fatal exception is thrown if the previous executable and this new one have
	 * exactly matching meta-data.  A fatal exception is thrown if meta-data has changed.
	 * All functions (FunctionDescriptions) associated with the executable are inserted,
	 * including their feature vectors.
	 * @param manager is the container of the executable
	 * @param exeRecord is the executable to insert
	 * @return false only if the insert was unsuccessful but a previous executable could not be recovered
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException if update differences cannot reconciled 
	 * @throws DatabaseNonFatalException for non-fatal updates that can't be executed
	 */
	private boolean insertExe(DescriptionManager manager, ExecutableRecord exeRecord)
			throws ElasticException, LSHException, DatabaseNonFatalException {
		RowKeyElastic eKey = updateKey(manager, exeRecord);
		String exeId = eKey.generateExeIdString();

		if (!insertExecutableRecord(exeRecord, exeId)) {	// Try to insert the executable
			JSONObject exeObj = queryMd5ExeMatch(exeRecord.getMd5());
			if (exeObj != null) {		// Try to retrieve the previous version
				ExecutableRecord oldrec = makeExecutableRecordTemp(exeObj);
				int cmp = oldrec.compareMetadata(exeRecord);
				if (cmp != 0) {
					String fatalerror =
						FunctionDatabase.constructFatalError(cmp, exeRecord, oldrec);
					if (fatalerror != null) {
						throw new LSHException(fatalerror);
					}
					throw new DatabaseNonFatalException(
						FunctionDatabase.constructNonfatalError(cmp, exeRecord, oldrec));
				}
				throw new DatabaseNonFatalException(
					exeRecord.getNameExec() + " is already ingested");
			}
			return false;		// Indicate this executable already inserted
		}
		int newIds = 0;
		long baseId = 0;
		Iterator<FunctionDescription> iter = manager.listFunctions(exeRecord);
		while (iter.hasNext()) {			// Count the functions to insert for this executable
			iter.next();
			newIds += 1;
		}
		baseId = allocateFunctionIndexSpace(newIds);		// Allocated the ids we will need
		iter = manager.listFunctions(exeRecord);
		while (iter.hasNext()) {
			manager.setFunctionDescriptionId(iter.next(), new RowKeyElastic(baseId));	// Set the (allocated) ids
			baseId += 1;
		}
		// Collect/dedup vectors and update SignatureRecords with vector ids, before writing FunctionDescriptions
		Set<IdHistogram> vectorContainer =
			IdHistogram.collectVectors(manager, manager.listFunctions(exeRecord));

		iter = manager.listFunctions(exeRecord);
		// Write the FunctionDescriptions now that vector ids are filled in
		while (iter.hasNext()) {
			insertFunctionRange(manager, exeRecord, eKey, exeId, iter, MAX_FUNCTION_BULK);
		}

		// Create/update the vector documents
		Iterator<IdHistogram> viter = vectorContainer.iterator();
		while (viter.hasNext()) {
			insertVectorRange(viter, MAX_VECTOR_BULK);
		}
		return true;
	}

	/**
	 * Create configuration index, containing the keyvalue pairs
	 * and the sequence counter for ExecutableRecord/FunctionDescription document ids
	 * @throws ElasticException for communication problems with the server
	 */
	private void createConfigurationIndex() throws ElasticException {
		StringBuilder builder = new StringBuilder();
		builder.append("{ \"settings\": { ");
		builder.append("    \"number_of_shards\": 1, ");
		builder.append("    \"auto_expand_replicas\": \"0-all\" }, ");
		builder.append("  \"mappings\": { ");
		builder.append("    \"dynamic\": \"strict\", ");
		builder.append("    \"properties\": { ");
		builder.append("      \"type\": { ");				// Can be "sequence"  or  "keyvalue"
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"iid\": { ");
		builder.append("        \"type\": \"long\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"value\": { ");
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"index\": false } } } }");
		connection.executeStatementNoResponse(ElasticConnection.PUT, "configuration",
			builder.toString());

		// Make sure initial counter document exists and initializes counter to 1
		connection.executeStatementNoResponse(ElasticConnection.PUT, "configuration/_doc/1",
			"{ \"type\": \"sequence\", \"iid\": 1 }");
	}

	/**
	 * Allocate a specific number of ids for function documents.  The document id for a function
	 * is an integer unique across the entire database. Allocation of this id is implemented as an integer
	 * counter stored in a single document. Updating this document for an allocation must take into account
	 * distributed nodes simultaneously requesting ids.
	 * @param amount is the number of ids to allocate
	 * @return the first integer in the newly allocated set of ids
	 * @throws ElasticException for communication problems with the server
	 */
	private long allocateFunctionIndexSpace(int amount) throws ElasticException {
		String body =
			"{ \"script\": { \"inline\": \"ctx._source.iid += params.bulk_size\", \"params\": { \"bulk_size\": " +
				Integer.toString(amount) + "}}}";
		JSONObject resp = connection.executeStatement(ElasticConnection.POST,
			"configuration/_update/1?_source=iid&retry_on_conflict=5", body);
		JSONObject get = (JSONObject) resp.get("get");
		JSONObject fields = (JSONObject) get.get("_source");
		long res = (Long) fields.get("iid");
		return res - amount;
	}

	/**
	 * Insert a set of vector documents.  Update/create the corresponding meta documents that
	 * count the number of times unique vectors are multiply inserted. Take into account simultaneous
	 * updates from distributed nodes. The vectors are presented as an iterator to IdHistogram, with
	 * the vectors already locally deduped and counted.  This routine submits one bulk insertion/update
	 * request, including unique vectors only up to a specified maximum. The iterator is advanced for
	 * each unique vector included with the one request.
	 * @param iter is the iterator to unique vectors and counts (IdHistogram)
	 * @param maxVectors is the maximum number of unique vectors to include in this one request
	 * @throws ElasticException for communication problems with the server
	 */
	private void insertVectorRange(Iterator<IdHistogram> iter, int maxVectors)
			throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		do {
			IdHistogram entry = iter.next();
			// Create the document <repo>_vector/vector if it doesn't already exist
			buffer.append("{ \"create\": { \"_index\": \"")
					.append(repository)
					.append("_vector\", ");
			buffer.append("\"_id\": \"");
			Base64Lite.encodeLongBase64(buffer, entry.id);
			buffer.append("\" } }\n");
			buffer.append("{ \"features\": \"");
			entry.vec.saveBase64(buffer, Base64Lite.encode);
			buffer.append("\" }\n");
			// Upsert the counter document <repo>_vector/meta
			buffer.append("{ \"update\": { \"_index\": \"").append(repository).append("_meta\", ");
			buffer.append("\"_id\": \"");
			Base64Lite.encodeLongBase64(buffer, entry.id);
			buffer.append("\", \"retry_on_conflict\": 5 } }\n");
			buffer.append("{ \"script\": { \"inline\": \"ctx._source.count += params.count\", ");
			buffer.append("\"params\": { \"count\": ").append(entry.count).append("} },");
			buffer.append("\"upsert\": { \"count\": ").append(entry.count).append("} }\n");
			maxVectors -= 1;
			if (maxVectors <= 0) {
				break;
			}
		}
		while (iter.hasNext());
		JSONObject resp = connection.executeBulk("/_bulk", buffer.toString());
		if ((Boolean) resp.get("errors")) {
			JSONArray items = (JSONArray) resp.get("items");
			for (Object item2 : items) {
				JSONObject item = (JSONObject) item2;
				JSONObject create = (JSONObject) item.get("create");
				JSONObject error = null;
				if (create != null) {
					error = (JSONObject) create.get("error");
					if (error != null) {
						String type = (String) error.get("type");
						if (type.startsWith("version_conflict")) {
							continue;			// Normal error, meaning document already exists
						}
					}
				}
				else {
					JSONObject update = (JSONObject) item.get("update");
					error = (JSONObject) update.get("error");
				}
				if (error != null) {
					throw new ElasticException((String) error.get("reason"));
				}
			}
		}
	}

	/**
	 * Decrement the "meta" document counter by the histogram count for a set of vectors.  If any counter reaches zero,
	 * delete the meta document and add the vector record to the list of vectors scheduled for full deletion.
	 * @param deleteList accumulates records of counters that have reached zero
	 * @param iter1 is an iterator over records indicating the vector id and the count to decrement by
	 * @param iter2 is a copy of the first iterator
	 * @param maxVectors is the maximum number of counter updates to issue in this window
	 * @throws ElasticException for communication problems with the server
	 */
	private void decrementVectorCounters(List<IdHistogram> deleteList, Iterator<IdHistogram> iter1,
			Iterator<IdHistogram> iter2, int maxVectors) throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		for (int i = 0; i < maxVectors; ++i) {
			if (!iter1.hasNext()) {
				break;
			}
			IdHistogram entry = iter1.next();
			buffer.append("{ \"update\": { \"_index\": \"").append(repository).append("_meta\", ");
			buffer.append("\"_id\": \"");
			Base64Lite.encodeLongBase64(buffer, entry.id);
			buffer.append("\", \"retry_on_conflict\": 5 } }\n");
			buffer.append(
				"{ \"script\": { \"inline\": \"if ((ctx._source.count -= params.count) <=0) { ctx.op = \\\"delete\\\" }\", ");
			buffer.append("\"params\": { \"count\": ").append(entry.count).append("} } }\n");
			maxVectors -= 1;
		}
		JSONObject resp = connection.executeBulk("/_bulk", buffer.toString());
		JSONArray items = (JSONArray) resp.get("items");
		for (int i = 0; i < maxVectors; ++i) {
			if (!iter2.hasNext()) {
				break;
			}
			IdHistogram entry = iter2.next();
			JSONObject item = (JSONObject) items.get(i);
			JSONObject update = (JSONObject) item.get("update");
			long id = Base64Lite.decodeLongBase64((String) update.get("_id"));
			if (id != entry.id) {
				throw new ElasticException("Mismatch in decrementVectorCounters");
			}
			if ("deleted".equals(update.get("result"))) {
				deleteList.add(entry);				// Mark this vector for full deletion
			}
		}
	}

	/**
	 * Delete vector documents in bulk. This assumes multiplicity counts in the "meta" documents
	 * have already been checked, and these vectors are scheduled for full document deletion.
	 * Vectors are presented as an iterator to IdHistograms. One bulk deletion request is
	 * submitted containing vectors up to a given maximum number. The iterator is advanced by
	 * the number submitted
	 * @param iter is an iterator over records containing the id's to delete
	 * @param maxVectors is the maximum number to delete for this window
	 * @throws ElasticException for communication problems with the server
	 */
	private void deleteRawVectors(Iterator<IdHistogram> iter, int maxVectors)
			throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		do {
			IdHistogram entry = iter.next();
			buffer.append("{ \"delete\": { \"_index\": \"")
					.append(repository)
					.append("_vector\", ");
			buffer.append("\"_id\": \"");
			Base64Lite.encodeLongBase64(buffer, entry.id);
			buffer.append("\" } }\n");
			maxVectors -= 1;
		}
		while (iter.hasNext() && maxVectors > 0);
		JSONObject resp = connection.executeBulk("/_bulk", buffer.toString());
		if ((Boolean) resp.get("errors")) {
			throw new ElasticException("Error during vector deletion");
		}
	}

	/**
	 * Delete function documents and exe document associated with an executable id
	 * @param exeId is the executable's document id
	 * @return the number of function documents deleted
	 * @throws ElasticException for communication problems with the server
	 */
	private int deleteExeDocuments(String exeId) throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"query\": {");
		buffer.append("  \"parent_id\": {");
		buffer.append("    \"type\": \"function\",");
		buffer.append("    \"id\": \"").append(exeId).append("\" } } }");
		JSONObject resp = connection.executeStatement(ElasticConnection.POST,
			"executable/_delete_by_query", buffer.toString());
		long numDocs = (Long) resp.get("deleted");
		connection.executeURIOnly(ElasticConnection.DELETE, "executable/_doc/" + exeId);
		return (int) numDocs;
	}

	/**
	 * Append configuration WeightFactory weights to a JSON document in progress
	 * @param builder accumulates the encoded weights
	 * @param config is the Configuration
	 */
	private static void appendWeightSettings(StringBuilder builder, Configuration config) {
		double[] weightArray = config.weightfactory.toArray();
		builder.append('\"').append(weightArray[0]);
		for (int i = 1; i < weightArray.length; ++i) {
			builder.append(' ').append(weightArray[i]);
		}
		builder.append("\" ");
	}

	/**
	 * Append configuration IDFLookup hashes to a JSON document in progress
	 * @param builder accumulates the encoded hashes
	 * @param config is the Configuration
	 */
	private static void appendLookupSettings(StringBuilder builder, Configuration config) {
		int[] intArray = config.idflookup.toArray();
		builder.append('\"').append(intArray[0]);
		for (int i = 1; i < intArray.length; ++i) {
			builder.append(' ').append(intArray[i]);
		}
		builder.append("\" ");
	}

	/**
	 * Adjust the number of replicas and the refresh rate for the database.
	 * Different settings may make sense depending on whether the database is
	 * doing a large ingest or is currently only responding to queries
	 * @param index is the specific database index to adjust
	 * @param numReplicas is the number of replicas (data replication) requested
	 * @param refreshRateInSecs is the refresh rate requested
	 * @throws ElasticException for communication problems with the server
	 */
	private void adjustReplicaRefresh(String index, int numReplicas, int refreshRateInSecs)
			throws ElasticException {
		StringBuilder builder = new StringBuilder();
		builder.append("{ \"index\": { ");
		builder.append("  \"number_of_replicas\": ").append(numReplicas).append(", ");
		builder.append("  \"refresh_interval\": \"");
		if (refreshRateInSecs < 1) {
			builder.append("-1");		// Indicates that no refreshes are scheduled
		}
		else {
			builder.append(refreshRateInSecs).append('s');
		}
		builder.append("\" } }");
		JSONObject resp = connection.executeStatement(ElasticConnection.PUT, index + "/_settings",
			builder.toString());
		Boolean ack = (Boolean) resp.get("acknowledged");
		if (ack == null) {
			throw new ElasticException(
				"Unknown response trying to adjust number_of_replicas and refresh_interval");
		}
		if (!ack) {
			throw new ElasticException("Cluster did not accept settings for index: " + index);
		}
	}

	/**
	 * This routine establishes the schema for the "vector" and "meta" document types
	 * for a new database. It also sets up weights and hashes for the vector tokenizer (lsh_tokenizer).
	 * @param config contains database configuration info
	 * @throws ElasticException for communication problems with the server
	 */
	private void createVectorIndex(Configuration config) throws ElasticException {
		StringBuilder builder = new StringBuilder();
		builder.append("{ \"settings\": { ");
		builder.append("  \"index\": { ");
		builder.append("    \"analysis\": { ");
		builder.append("      \"tokenizer\": { ");
		builder.append("        \"lsh_").append(repository).append("\": { ");
		builder.append("          \"type\": \"lsh_tokenizer\", ");
		builder.append("          \"").append(ElasticUtilities.LSH_WEIGHTS).append("\": ");
		appendWeightSettings(builder, config);
		builder.append(",         \"").append(ElasticUtilities.IDF_CONFIG).append("\": ");
		appendLookupSettings(builder, config);
		builder.append(",         \"")
				.append(ElasticUtilities.K_SETTING)
				.append("\": ")
				.append(config.k);
		builder.append(",         \"")
				.append(ElasticUtilities.L_SETTING)
				.append("\": ")
				.append(config.L);
		builder.append(" } }, ");
		builder.append("      \"analyzer\": { ");
		builder.append("        \"lsh_analyzer\": { ");
		builder.append("          \"type\": \"custom\", ");
		builder.append("          \"tokenizer\": \"lsh_")
				.append(repository)
				.append("\" } } } } }, ");
		builder.append("  \"mappings\": { ");
		builder.append("    \"properties\": { ");
		builder.append("      \"features\": { ");
		builder.append("        \"type\": \"text\", ");
		builder.append("        \"norms\": false, ");
		builder.append("        \"index_options\": \"freqs\", ");
		builder.append("        \"analyzer\": \"lsh_analyzer\" } } } }");
		connection.executeStatementNoResponse(ElasticConnection.PUT, "vector", builder.toString());

		builder = new StringBuilder();
		builder.append("{ \"mappings\": { ");
		builder.append("    \"properties\": { ");
		builder.append("      \"count\": { ");
		builder.append("        \"type\": \"integer\", ");
		builder.append("        \"index\": false } } } }");
		connection.executeStatementNoResponse(ElasticConnection.PUT, "meta", builder.toString());
	}

	/**
	 * This routine establishes the schema for "exe" and "function" document types in a new database.
	 * @throws ElasticException for communication problems with the server
	 */
	private void createExecutableIndex() throws ElasticException {
		StringBuilder builder = new StringBuilder();
		builder.append("{ \"mappings\": { ");
		builder.append("    \"properties\": { ");
		builder.append("      \"md5\": { ");				// "exe" properties
		builder.append("        \"type\": \"keyword\" }, ");
		builder.append("      \"name_exec\": { ");
		builder.append("        \"type\": \"keyword\" }, ");
		builder.append("      \"architecture\": { ");
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"name_compiler\": { ");
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"ingest_date\": { ");
		builder.append("        \"type\": \"date\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"repository\": { ");
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"path\": { ");
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"execategory\": { ");
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"name_func\": { ");			// "function" properties
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"doc_values\": false }, ");
		builder.append("      \"id_signature\": { ");
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"doc_values\": false }, ");
		builder.append("      \"flags\": { ");
		builder.append("        \"type\": \"integer\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"addr\": { ");
		builder.append("        \"type\": \"long\", ");
		builder.append("        \"doc_values\": false }, ");
		builder.append("      \"childid\": { ");
		builder.append("        \"type\": \"keyword\", ");
		builder.append("        \"index\": false }, ");
		builder.append("      \"join_field\": { ");			// parent/child relation between exe and function
		builder.append("        \"type\": \"join\", ");
		builder.append("        \"relations\": { ");
		builder.append("          \"exe\": \"function\" }, ");
		builder.append("        \"eager_global_ordinals\": true } } } }");

		connection.executeStatementNoResponse(ElasticConnection.PUT, "executable",
			builder.toString());
	}

	/**
	 * Construct the database connection given a URL.  The URL protocol must be http, and the URL
	 * path must contain exactly one element naming the particular repository on the server.
	 * @param baseURL is the http URL
	 * @throws MalformedURLException if the URL is malformed
	 */
	public ElasticDatabase(URL baseURL) throws MalformedURLException {
		String fullURL = baseURL.toString();
		if (fullURL.startsWith("elastic:")) {
			// https is the true protocol
			fullURL = "https:" + fullURL.substring(8);
		}

		String path = baseURL.getPath();
		if (!fullURL.endsWith(path)) {
			throw new MalformedURLException("URL path must indicate the repository only");
		}
		repository = path.substring(1);
		this.serverInfo =
			new BSimServerInfo(DBType.elastic, baseURL.getHost(), baseURL.getPort(), repository);
		this.baseURL = fullURL.substring(0, fullURL.length() - path.length());

		lastError = null;
		info = null;
		status = Status.Unconnected;
		initialized = false;
	}

	/**
	 * @return true if a connection has been successfully initialized
	 */
	public boolean isInitialized() {
		return initialized;
	}

	/**
	 * Read database configuration ("keyvalue" documents) into a key/value pair map.
	 * @return the populated map
	 * @throws ElasticException for communication problems with the server
	 * @throws NoDatabaseException if the database (as opposed to the server) does not exist
	 */
	private Map<String, String> readKeyValues() throws ElasticException, NoDatabaseException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"size\": 500, \"query\": { \"match_all\": {} } }");
		JSONObject resp;
		try {
			resp = connection.executeStatement(ElasticConnection.GET, "configuration/_search",
				buffer.toString());
		}
		catch (ElasticException ex) {
			if (ex.getMessage().contains("index_not_found_exception")) {
				throw new NoDatabaseException("Database instance does not exist");
			}
			throw ex;
		}
		JSONObject baseHits = (JSONObject) resp.get("hits");
		long total = 0;
		if (baseHits != null) {
			JSONObject totalRec = (JSONObject) baseHits.get("total");
			total = (Long) totalRec.get("value");
		}
		if (total <= 1) {
			throw new ElasticException("Unrecoverable error: Could not find configuration");
		}
		HashMap<String, String> res = new HashMap<>();
		JSONArray hits = (JSONArray) baseHits.get("hits");
		for (Object hit2 : hits) {
			JSONObject hit = (JSONObject) hit2;
			String key = (String) hit.get("_id");
			JSONObject source = (JSONObject) hit.get("_source");
			Object value = source.get("value");
			if (value == null) {
				continue;		// This might be the "sequence" document
			}
			res.put(key, (String) value);
		}
		return res;
	}

	/**
	 * Given a critical key in the database configuration, return its corresponding value
	 * @param key is the configuration key
	 * @param keyValue is the key/value map
	 * @return the corresponding value
	 * @throws ElasticException if the key is missing
	 */
	private String getCriticalValue(String key, Map<String, String> keyValue)
			throws ElasticException {
		String value = keyValue.get(key);
		if (value == null) {
			throw new ElasticException("Missing critical configuration value: " + key);
		}
		return value;
	}

	/**
	 * Write DatabaseInformation to database in one bulk request. If -k- and -L- are greater than zero, they are written as well
	 * @param k (optional) is the database k parameter
	 * @param L (optional) is the database L parameter
	 * @throws ElasticException for communication problems with the server
	 */
	private void writeBasicInfo(int k, int L) throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"index\": { \"_id\": \"name\" } }\n");
		buffer.append("{ \"type\": \"keyvalue\", \"value\": \"")
				.append(info.databasename)
				.append("\" }\n");
		buffer.append("{ \"index\": { \"_id\": \"owner\" } }\n");
		buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
				.append(info.owner)
				.append("\" }\n");
		buffer.append("{ \"index\": { \"_id\": \"description\" } }\n");
		buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
				.append(info.description)
				.append("\" }\n");
		buffer.append("{ \"index\": { \"_id\": \"major\" } }\n");
		buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
				.append(Short.toString(info.major))
				.append("\" }\n");
		buffer.append("{ \"index\": { \"_id\": \"minor\" } }\n");
		buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
				.append(Short.toString(info.minor))
				.append("\" }\n");
		buffer.append("{ \"index\": { \"_id\": \"settings\" } }\n");
		buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
				.append(Integer.toString(info.settings))
				.append("\" }\n");
		buffer.append("{ \"index\": { \"_id\": \"readonly\" } }\n");
		buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
				.append(SpecXmlUtils.encodeBoolean(info.readonly))
				.append("\" }\n");
		buffer.append("{ \"index\": { \"_id\": \"trackcallgraph\" } }\n");
		buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
				.append(SpecXmlUtils.encodeBoolean(info.trackcallgraph))
				.append("\" }\n");
		buffer.append("{ \"index\": { \"_id\": \"layout\" } }\n");
		buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
				.append(Integer.toString(info.layout_version))
				.append("\" }\n");
		buffer.append("{ \"index\": { \"_id\": \"datecolumn\" } }\n");
		String datecol = (info.dateColumnName == null) ? "Ingest Date" : info.dateColumnName;
		buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"").append(datecol).append("\" }\n");
		if (k > 0) {
			buffer.append("{ \"index\": { \"_id\": \"k\" } }\n");
			buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
					.append(Integer.toString(k))
					.append("\" }\n");
			buffer.append("{ \"index\": { \"_id\": \"L\" } }\n");
			buffer.append("{ \"type\": \"keyvalue\",  \"value\": \"")
					.append(Integer.toString(L))
					.append("\" }\n");
		}
		connection.executeBulk('/' + repository + '_' + "configuration/_bulk", buffer.toString());
		writeExecutableCategories();
		writeFunctionTags();
	}

	/**
	 * Extract category information for this database into the DatabaseInformation object
	 * from the key/value map. Category information is stored as keys: execatcount, execat1, execat2, ...
	 * @param infoResult is the information object to populate
	 * @param keyValue is the map of key/value pairs
	 * @throws ElasticException for communication problems with the server
	 */
	private void readExecutableCategories(DatabaseInformation infoResult,
			Map<String, String> keyValue) throws ElasticException {
		String countString = keyValue.get("execatcount");
		int count;
		if (countString != null) {
			count = Integer.parseInt(countString);
		}
		else {
			count = 0;				// key may not be present, assume 0 categories
		}
		if (count <= 0) {
			infoResult.execats = null;
			return;
		}
		infoResult.execats = new ArrayList<>();
		for (int i = 0; i < count; ++i) {
			String key = "execat" + (i + 1);
			String value = getCriticalValue(key, keyValue);
			infoResult.execats.add(value);
		}
	}

	/**
	 * Extract function tag information for this database into the DatabaseInformation object
	 * from the key/value map. Tag information is stored as keys: functiontagcount, functiontag1, functiontag2, ...
	 * @param infoResult is the information object that will hold results
	 * @param keyValue is the keyword->value map for the database
	 * @throws ElasticException if a critical function tag key is missing
	 */
	private void readFunctionTags(DatabaseInformation infoResult, Map<String, String> keyValue)
			throws ElasticException {
		String countString = keyValue.get("functiontagcount");
		int count;
		if (countString != null) {
			count = Integer.parseInt(countString);
		}
		else {
			count = 0;				// key may not be present,  assume 0 tags
		}
		if (count <= 0) {
			infoResult.functionTags = null;
			return;
		}
		infoResult.functionTags = new ArrayList<>();
		for (int i = 0; i < count; ++i) {
			String key = "functiontag" + (i + 1);
			String value = getCriticalValue(key, keyValue);
			infoResult.functionTags.add(value);
		}
	}

	/**
	 * Write out executable category information for this database as "keyvalue" documents
	 * @throws ElasticException for communication problems with the server
	 */
	private void writeExecutableCategories() throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		if (info.execats == null) {
			buffer.append("{ \"index\": { \"_id\": \"execatcount\" } }\n");
			buffer.append("{ \"type\": \"keyvalue\", \"value\": \"0\"}\n");
		}
		else {
			buffer.append("{ \"index\": { \"_id\": \"execatcount\" } }\n");
			buffer.append("{ \"type\": \"keyvalue\", \"value\": \"")
					.append(info.execats.size())
					.append("\" }\n");
			for (int i = 0; i < info.execats.size(); ++i) {
				buffer.append("{ \"index\": { \"_id\": \"execat").append(i + 1).append("\" } }\n");
				buffer.append("{ \"type\": \"keyvalue\", \"value\": \"")
						.append(info.execats.get(i))
						.append("\" }\n");
			}
		}
		connection.executeBulk('/' + repository + '_' + "configuration/_bulk", buffer.toString());
	}

	/**
	 * Write out function tag information for this database as "keyvalue" documents
	 * @throws ElasticException for communication problems with the server
	 */
	private void writeFunctionTags() throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		if (info.functionTags == null) {
			buffer.append("{ \"index\": { \"_id\": \"functiontagcount\" } }\n");
			buffer.append("{ \"type\": \"keyvalue\", \"value\": \"0\"}\n");
		}
		else {
			buffer.append("{ \"index\": { \"_id\": \"functiontagcount\" } }\n");
			buffer.append("{ \"type\": \"keyvalue\", \"value\": \"")
					.append(info.functionTags.size())
					.append("\" }\n");
			for (int i = 0; i < info.functionTags.size(); ++i) {
				buffer.append("{ \"index\": { \"_id\": \"functiontag")
						.append(i + 1)
						.append("\" } }\n");
				buffer.append("{ \"type\": \"keyvalue\", \"value\": \"")
						.append(info.functionTags.get(i))
						.append("\" }\n");
			}
		}
		connection.executeBulk('/' + repository + '_' + "configuration/_bulk", buffer.toString());
	}

	/**
	 * Read all of the basic database configuration information from the "keyvalue" documents
	 * @param config is the Configuration object to fill in with the info
	 * @throws ElasticException for communication problems with the server
	 * @throws NoDatabaseException if the specific database does not exist on the server
	 */
	private void readBasicInfo(Configuration config) throws ElasticException, NoDatabaseException {
		Map<String, String> keyValue = readKeyValues();
		config.info.databasename = getCriticalValue("name", keyValue);
		config.info.owner = getCriticalValue("owner", keyValue);
		config.info.description = getCriticalValue("description", keyValue);
		config.info.major = (short) SpecXmlUtils.decodeInt(getCriticalValue("major", keyValue));
		config.info.minor = (short) SpecXmlUtils.decodeInt(getCriticalValue("minor", keyValue));
		config.info.settings = SpecXmlUtils.decodeInt(getCriticalValue("settings", keyValue));
		config.info.readonly = SpecXmlUtils.decodeBoolean(getCriticalValue("readonly", keyValue));
		config.info.trackcallgraph =
			SpecXmlUtils.decodeBoolean(getCriticalValue("trackcallgraph", keyValue));
		config.info.layout_version = SpecXmlUtils.decodeInt(getCriticalValue("layout", keyValue));
		config.info.dateColumnName = getCriticalValue("datecolumn", keyValue);
		if (config.info.dateColumnName.equals("Ingest Date")) {
			// name
			config.info.dateColumnName = null; // Don't bother holding it
		}
		config.k = SpecXmlUtils.decodeInt(getCriticalValue("k", keyValue));
		config.L = SpecXmlUtils.decodeInt(getCriticalValue("L", keyValue));

		readExecutableCategories(config.info, keyValue);
		readFunctionTags(config.info, keyValue);
	}

	/**
	 * Change the password for specific user.  This assumes the ElasticSearch user
	 * in the native realm.
	 * @param uName is the user name
	 * @param password is the character data for the new password
	 * @throws ElasticException if the change is not successful
	 */
	private void changePasswordInternal(String uName, char[] password) throws ElasticException

	{
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"password\": \"");
		buffer.append(JSONObject.escape(String.valueOf(password)));
		buffer.append("\" }");
		StringBuilder path = new StringBuilder();
		path.append("/_security/user/_password");	// Ignore the username, change for "current" user
		connection.executeRawStatement(ElasticConnection.POST, path.toString(), buffer.toString());
	}

	/**
	 * Initialize a new BSim repository.  This does most of the work of reading
	 * configuration info and setting up the various factories.
	 * @param config is the Configuration object that is populated during initialization
	 * @throws ElasticException for communication problems with the server
	 * @throws NoDatabaseException if the specific database does not exist on the server
	 */
	private void initializeElastic(Configuration config)
			throws ElasticException, NoDatabaseException {
		connection = new ElasticConnection(baseURL, repository);
		if (baseURL.startsWith("https")) {
			connectionType = ConnectionType.SSL_Password_Authentication;
		}
		config.info = new DatabaseInformation();
		readBasicInfo(config);

		vectorFactory = new Base64VectorFactory();
		config.weightfactory = new WeightFactory();
		config.idflookup = new IDFLookup();
		JSONObject res;
		try {
			res = connection.executeURIOnly(ElasticConnection.GET, "vector/_settings");
		}
		catch (ElasticException ex) {
			if (ex.getMessage().contains("no such index")) {
				throw new NoDatabaseException(baseURL);
			}
			throw ex;
		}
		JSONObject repo = (JSONObject) res.get(repository + "_vector");
		JSONObject settings = (JSONObject) repo.get("settings");
		JSONObject index = (JSONObject) settings.get("index");
		JSONObject analysis = (JSONObject) index.get("analysis");
		JSONObject tokenizer = (JSONObject) analysis.get("tokenizer");
		String tokenizerName = null;
		for (Object obj : tokenizer.keySet()) {
			String key = (String) obj;
			if (key.startsWith("lsh_")) {
				tokenizerName = key;
				break;
			}
		}
		if (tokenizerName == null) {
			throw new ElasticException("Missing tokenizer configuration");
		}
		JSONObject tokenizerSettings = (JSONObject) tokenizer.get(tokenizerName);
		String idfWeights = (String) tokenizerSettings.get(ElasticUtilities.LSH_WEIGHTS);
		String[] split = idfWeights.split(" ");
		double[] weightArray = new double[split.length];
		if (weightArray.length != config.weightfactory.getSize()) {
			throw new ElasticException("weighttable has wrong number of rows");
		}
		for (int i = 0; i < weightArray.length; ++i) {
			weightArray[i] = Double.parseDouble(split[i]);
		}
		config.weightfactory.set(weightArray);

		String lookup = (String) tokenizerSettings.get(ElasticUtilities.IDF_CONFIG);
		split = lookup.split(" ");
		int[] lookupArray = new int[split.length];
		for (int i = 0; i < lookupArray.length; ++i) {
			lookupArray[i] = Integer.parseInt(split[i]);
		}
		config.idflookup.set(lookupArray);
	}

	@Override
	public Status getStatus() {
		return status;
	}

	@Override
	public ConnectionType getConnectionType() {
		return connectionType;
	}

	@Override
	public String getUserName() {
		if (userName != null) {
			return userName;
		}
		return ClientUtil.getUserName();
	}

	@Override
	public void setUserName(String userName) {
		this.userName = userName;
	}

	@Override
	public LSHVectorFactory getLSHVectorFactory() {
		return vectorFactory;
	}

	@Override
	public DatabaseInformation getInfo() {
		return info;
	}

	@Override
	public int compareLayout() {
		if (info.layout_version == ElasticDatabase.LAYOUT_VERSION) {
			return 0;
		}
		return (info.layout_version < ElasticDatabase.LAYOUT_VERSION) ? -1 : 1;
	}

	@Override
	public BSimServerInfo getServerInfo() {
		return serverInfo;
	}

	@Override
	public String getURLString() {
		return baseURL + '/' + repository;
	}

	@Override
	public boolean initialize() {
		if (initialized) {
			return true;
		}
		try {
			ClientUtil.getClientAuthenticator();	// Make sure an authenticator is installed
			final Configuration config = new Configuration();
			initializeElastic(config);
			info = config.info;
			vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);
		}
		catch (ElasticException err) {
			lastError = new Error(ErrorCategory.Initialization,
				"Database error on initialization: " + err.getMessage());
			status = Status.Error;
			return false;
		}
		catch (NoDatabaseException err) {
			info = null;
			lastError = new Error(ErrorCategory.Nodatabase,
				"Database has not been created yet: " + err.getMessage());
			initialized = true;
			status = Status.Ready;
			return true;
		}
		status = Status.Ready;
		initialized = true;
		return true;
	}

	@Override
	public void close() {
		if (connection != null) {
			connection.close();
			connection = null;
		}
		status = Status.Unconnected;
		initialized = false;
		info = null;
	}

	@Override
	public Error getLastError() {
		return lastError;
	}

	@Override
	public QueryResponseRecord query(BSimQuery<?> query) {
		if ((!isInitialized()) && (!(query instanceof CreateDatabase))) {
			lastError = new Error(ErrorCategory.Nodatabase, "The database does not exist");
			return null;
		}
		lastError = null;
		try {
			query.buildResponseTemplate();
			if (query instanceof QueryNearest) {
				fdbQueryNearest((QueryNearest) query);
			}
			else if (query instanceof QueryNearestVector) {
				fdbQueryNearestVector((QueryNearestVector) query);
			}
			else if (query instanceof InsertRequest) {
				fdbDatabaseInsert((InsertRequest) query);
			}
			else if (query instanceof QueryInfo) {
				fdbDatabaseInfo((QueryInfo) query);
			}
			else if (query instanceof QueryName) {
				fdbQueryName((QueryName) query);
			}
			else if (query instanceof QueryExeInfo) {
				fdbQueryExeInfo((QueryExeInfo) query);
			}
			else if (query instanceof QueryExeCount) {
				fdbQueryExeCount((QueryExeCount) query);
			}
			else if (query instanceof CreateDatabase) {
				fdbDatabaseCreate((CreateDatabase) query);
			}
			else if (query instanceof QueryChildren) {
				fdbQueryChildren((QueryChildren) query);
			}
			else if (query instanceof QueryDelete) {
				fdbDelete((QueryDelete) query);
			}
			else if (query instanceof QueryUpdate) {
				fdbUpdate((QueryUpdate) query);
			}
			else if (query instanceof QueryVectorId) {
				fdbQueryVectorId((QueryVectorId) query);
			}
			else if (query instanceof QueryVectorMatch) {
				fdbQueryVectorMatch((QueryVectorMatch) query);
			}
			else if (query instanceof QueryPair) {
				fdbQueryPair((QueryPair) query);
			}
			else if (query instanceof InstallCategoryRequest) {
				fdbInstallCategory((InstallCategoryRequest) query);
			}
			else if (query instanceof InstallTagRequest) {
				fdbInstallTag((InstallTagRequest) query);
			}
			else if (query instanceof InstallMetadataRequest) {
				fdbInstallMetadata((InstallMetadataRequest) query);
			}
			else if (query instanceof AdjustVectorIndex) {
				fdbAdjustVectorIndex((AdjustVectorIndex) query);
			}
			else if (query instanceof PrewarmRequest) {
				fdbPrewarm((PrewarmRequest) query);
			}
			else if (query instanceof PasswordChange) {
				fdbPasswordChange((PasswordChange) query);
			}
			else {
				lastError = new Error(ErrorCategory.Fatal, "Unknown query type");
				query.clearResponse();
			}
		}
		catch (DatabaseNonFatalException err) {
			lastError = new Error(ErrorCategory.Nonfatal,
				"Skipping -" + query.getName() + "- : " + err.getMessage());
			query.clearResponse();
		}
		catch (LSHException err) {
			lastError = new Error(ErrorCategory.Fatal,
				"Fatal error during -" + query.getName() + "- : " + err.getMessage());
			query.clearResponse();
		}
		catch (ElasticException err) {
			lastError = new Error(ErrorCategory.Fatal,
				"Elastic error during -" + query.getName() + "- : " + err.getMessage());
			query.clearResponse();
		}
		return query.getResponse();
	}

	/**
	 * Create a new database
	 * @param config is the configuration information for the database
	 * @throws ElasticException for communication problems with the server
	 */
	private void generate(Configuration config) throws ElasticException {
		config.info.layout_version = ElasticDatabase.LAYOUT_VERSION;
		info = config.info;
		vectorFactory = new Base64VectorFactory();
		vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);

		connection = new ElasticConnection(baseURL, repository);

		createConfigurationIndex();
		createExecutableIndex();
		createVectorIndex(config);
		writeBasicInfo(config.k, config.L);

		status = Status.Ready;
		initialized = true;
	}

	/**
	 * Given the name of an executable library, its architecture, and a function name,
	 * return the id of the document describing this specific function.
	 * These 3 Strings are designed to uniquely identify a library function.
	 * @param exeName is the name of the executable
	 * @param funcName is the name of the function
	 * @param arch is the executable architecture
	 * @return the document id of the matching function
	 * @throws ElasticException if the function (the executable) doesn't exist
	 */
	public String recoverExternalFunctionId(String exeName, String funcName, String arch)
			throws ElasticException {
		String md5 = ExecutableRecord.calcLibraryMd5Placeholder(exeName, arch);
		JSONObject row = queryMd5ExeMatch(md5);
		if (row == null) {
			throw new ElasticException(
				"Could not resolve filter specifying executable: " + exeName);
		}
		String exeId = (String) row.get("_id");
		JSONArray descres = queryFuncNameMatch(exeId, funcName, 2);
		if (1 != descres.size()) {
			throw new ElasticException(
				"Could not resolve filter specifying function: [" + exeName + "]" + funcName);
		}
		RowKeyElastic eKey = RowKeyElastic.parseExeIdString(exeId);
		StringBuilder buffer = new StringBuilder();
		eKey.generateLibraryFunctionId(buffer, funcName);
		return buffer.toString();
	}

	/**
	 * For every function currently in the manager, fill in its call-graph information.
	 * This involves querying the database for child information, adding the cross-link
	 * information (CallgraphEntry) between FunctionDescriptions, and possibly querying
	 * for new library executables and functions
	 * @param manager is the collection of functions to link
	 * @throws LSHException for problems updating the container
	 * @throws ElasticException for communication problems with the server
	 */
	private void queryCallgraph(DescriptionManager manager) throws LSHException, ElasticException {
		if (!info.trackcallgraph) {
			throw new LSHException("Database does not track callgraph");
		}
		TreeMap<RowKey, FunctionDescription> funcmap = new TreeMap<>();
		manager.generateFunctionIdMap(funcmap);
		for (ExecutableRecord exeRec : manager.getExecutableRecordSet()) {
			if (exeRec.isLibrary()) {
				continue;
			}
			List<FunctionDescription> funclist = new ArrayList<>();
			Iterator<FunctionDescription> iter = manager.listFunctions(exeRec);
			while (iter.hasNext()) { // Build a static copy of the list of functions
				funclist.add(iter.next());
			}
			for (FunctionDescription element : funclist) {
				fillinChildren(element, manager, funcmap);
			}
		}
	}

	/**
	 * Entry point for the Elasticsearch version of QueryName command:
	 *   Query for a specific executable and functions it contains
	 * @param query is command parameters
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems adding records to the response
	 */
	private void fdbQueryName(QueryName query) throws ElasticException, LSHException {
		ResponseName response = query.nameresponse;
		response.printselfsig = query.printselfsig;
		response.printjustexe = query.printjustexe;
		response.manage.setVersion(info.major, info.minor);
		response.manage.setSettings(info.settings);

		ExecutableRecord erec = findSingleExecutable(query.spec, response.manage);
		if (erec == null) {
			response.uniqueexecutable = false;
			return;
		}
		response.uniqueexecutable = true;

		queryByName(null, response.manage, erec, query.funcname, query.fillinSigs, query.maxfunc);
		if (query.fillinCallgraph) {
			queryCallgraph(response.manage);
		}
	}

	private String createExeFilter(String filterMd5, String filterExeName, String filterArch,
			String filterCompilerName, boolean includeFakes) {
		if (filterMd5 == null && filterExeName == null && filterArch == null &&
			filterCompilerName == null && includeFakes) {
			return null;
		}
		boolean placedFirst = false;
		StringBuilder buffer = new StringBuilder();
		buffer.append("\"filter\": [\n");
		if (filterMd5 != null) {
			if (filterMd5.length() == 32) {	// A complete md5
				buffer.append("{ \"term\" : { \"md5\" : \"");
				buffer.append(filterMd5);
				buffer.append("\" }}");
			}
			else {									// A partial md5 prefix
				buffer.append("{ \"prefix\" : { \"md5\" : \"");
				buffer.append(filterMd5);
				buffer.append("\" }}");
			}
			placedFirst = true;
		}
		if (filterExeName != null) {
			if (placedFirst) {
				buffer.append(",\n");
			}
			buffer.append("{ \"wildcard\" : {");
			buffer.append(" \"name_exec\" : {");
			buffer.append(" \"value\" : \"*");
			buffer.append(JSONObject.escape(filterExeName));
			buffer.append("*\" }}}");
			placedFirst = true;
		}
		if (filterArch != null || filterCompilerName != null) {
			if (placedFirst) {
				buffer.append(",\n");
			}
			buffer.append("{ \"script\": {");
			buffer.append("  \"script\": {");
			buffer.append("  \"inline\": \"");
			if (filterArch == null) {		// cname only
				buffer.append("doc['name_compiler'].value == params.comp");
			}
			else if (filterCompilerName == null) {	// arch only
				buffer.append("doc['architecture'].value == params.arch");
			}
			else {	// Both are provided
				buffer.append(
					"doc['name_compiler'].value == params.comp && doc['architecture'].value == params.arch");
			}
			buffer.append("\",");
			buffer.append("          \"params\": {");
			if (filterArch != null) {
				buffer.append(" \"arch\": \"").append(filterArch);
				if (filterCompilerName != null) {
					buffer.append("\", ");
				}
				else {
					buffer.append("\" ");
				}
			}
			if (filterCompilerName != null) {
				buffer.append(" \"comp\": \"").append(filterCompilerName).append("\" ");
			}
			buffer.append("}}}}");

		}
		buffer.append("]\n");
		if (!includeFakes) {
			buffer.append(", \"must_not\" : ");
			buffer.append("{ \"prefix\" : { \"md5\" : \"bbbbbbbbaaaaaaaa\" }}\n");
		}
		return buffer.toString();
	}

	private void fdbQueryExeCount(QueryExeCount query) throws ElasticException {
		ResponseExe response = query.exeresponse;
		String filter = createExeFilter(query.filterMd5, query.filterExeName, query.filterArch,
			query.filterCompilerName, query.includeFakes);
		response.recordCount = countExecutables(filter);
	}

	/**
	 * Queries the database for all executables matching the search criteria in the given
	 * {@link QueryExeInfo} object. Results are stored in the query info object
	 * 
	 * @param query the query information
	 * @throws ElasticException if there is an error executing the query
	 * @throws LSHException if there is an error executing the query
	 */
	private void fdbQueryExeInfo(QueryExeInfo query) throws ElasticException, LSHException {
		ResponseExe response = query.exeresponse;
		String filter = createExeFilter(query.filterMd5, query.filterExeName, query.filterArch,
			query.filterCompilerName, query.includeFakes);
		queryExecutables(response.manage, response.records, query.limit, null,
			query.sortColumn == ExeTableOrderColumn.MD5, filter);
		response.recordCount = response.records.size();
	}

	/**
	 * Entry point for the Elasticsearch version of CreateDatabase command:
	 *   Create a new database repository, with a specified configuration.
	 * @param query is command parameters
	 * @throws LSHException for problems loading the template
	 * @throws ElasticException for communication problems with the server
	 */
	private void fdbDatabaseCreate(CreateDatabase query) throws LSHException, ElasticException {
		ResponseInfo response = query.inforesponse;
		Configuration config = FunctionDatabase.loadConfigurationTemplate(query.config_template);
		// Copy in any overriding fields in the query
		if (query.info.databasename != null) {
			config.info.databasename = query.info.databasename;
		}
		if (query.info.owner != null) {
			config.info.owner = query.info.owner;
		}
		if (query.info.description != null) {
			config.info.description = query.info.description;
		}
		if (!query.info.trackcallgraph) {
			config.info.trackcallgraph = query.info.trackcallgraph;
		}
		if (query.info.functionTags != null) {
			checkStrings(query.info.functionTags, "function tags",
				FunctionTagBSimFilterType.MAX_TAG_COUNT);
			config.info.functionTags = query.info.functionTags;
		}
		if (query.info.execats != null) {
			checkStrings(query.info.execats, "categories", -1);
			config.info.execats = query.info.execats;
		}
		generate(config);
		response.info = config.info;
	}

	private static void checkStrings(List<String> list, String type, int limit)
			throws LSHException {
		if (limit > 0 && list.size() > limit) {
			throw new LSHException("Too many " + type + " specified (limit=" +
				FunctionTagBSimFilterType.MAX_TAG_COUNT + "): " + list.size());
		}
		Set<String> names = new HashSet<>();
		for (String name : list) {
			if (!CategoryRecord.enforceTypeCharacters(name)) {
				throw new LSHException("Bad characters in one or more proposed " + type);
			}
			if (!names.add(name)) {
				throw new LSHException("Duplicate " + type + " entry specified: " + name);
			}
		}
	}

	/**
	 * Entry point for the InstallCategoryRequest command:
	 *   Install a new executable category to be managed by the database
	 * @param query is command parameters
	 * @throws LSHException if the command is misconfigured
	 * @throws ElasticException for communication problems with the server
	 */
	private void fdbInstallCategory(InstallCategoryRequest query)
			throws LSHException, ElasticException {
		ResponseInfo response = query.installresponse;
		if (!CategoryRecord.enforceTypeCharacters(query.type_name)) {
			throw new LSHException("Bad characters in proposed category type");
		}
		if (query.isdatecolumn) {
			info.dateColumnName = query.type_name;
			StringBuilder buffer = new StringBuilder();
			buffer.append("{ \"type\": \"keyvalue\", \"value\": \"")
					.append(info.dateColumnName)
					.append("\" }");
			connection.executeStatementNoResponse(ElasticConnection.PUT, "configuration/datecolumn",
				buffer.toString());
			response.info = info;
			return;
		}
		// Check for existing category
		if (info.execats != null) {
			for (String cat : info.execats) {
				if (cat.equals(query.type_name)) {
					throw new LSHException("Executable category already exists");
				}
			}
		}
		if (info.execats == null) {
			info.execats = new ArrayList<>();
		}
		info.execats.add(query.type_name);
		writeExecutableCategories();
		response.info = info;
	}

	/**
	 * Entry point for the Elasticsearch version of InstallTagRequest command:
	 *   Install a new function tag to be managed by this data
	 * @param query is command parameters
	 * @throws LSHException if the command is misconfigured
	 * @throws ElasticException for communication problems with the server
	 */
	private void fdbInstallTag(InstallTagRequest query) throws LSHException, ElasticException {
		final ResponseInfo response = query.installresponse;
		if (!CategoryRecord.enforceTypeCharacters(query.tag_name)) {
			throw new LSHException("Bad characters in proposed function tag");
		}
		// Check for existing tag
		if (info.functionTags != null) {
			if (info.functionTags.contains(query.tag_name)) {
				throw new LSHException("Function tag already exists");
			}
		}
		if (info.functionTags == null) {
			info.functionTags = new ArrayList<>();
		}
		// There are only 32-bits of space in the function record reserved for storing the presence of tags
		if (info.functionTags.size() >= FunctionTagBSimFilterType.MAX_TAG_COUNT) {
			throw new LSHException(
				"Cannot allocate new function tag: " + query.tag_name + " - Column space is full");
		}
		info.functionTags.add(query.tag_name);
		writeFunctionTags();
		response.info = info;
	}

	/**
	 * Entry point for the Elasticsearch version of InstallMetadataRequest command:
	 *   Change some of the global meta-data labels for the database.
	 * @param query is command parameters
	 * @throws ElasticException for communication problems with the server
	 */
	private void fdbInstallMetadata(InstallMetadataRequest query) throws ElasticException {
		final ResponseInfo response = query.installresponse;
		if (query.dbname != null) {
			info.databasename = query.dbname;
		}
		if (query.owner != null) {
			info.owner = query.owner;
		}
		if (query.description != null) {
			info.description = query.description;
		}
		if (query.dbname != null || query.owner != null || query.description != null) {
			writeBasicInfo(0, 0);
		}
		response.info = info;
	}

	/**
	 * Entry point for the Elasticsearch version of AdjustVectorIndex command:
	 *   Adjust database settings pertinent to the main vector index
	 * @param query is command parameters
	 * @throws ElasticException for communication problems with the server
	 */
	private void fdbAdjustVectorIndex(AdjustVectorIndex query) throws ElasticException {
		final ResponseAdjustIndex response = query.adjustresponse;
		response.success = false;
		response.operationSupported = true;
		int numReplicas = query.doRebuild ? 1 : 0;
		int refreshRateInSecs = query.doRebuild ? 1 : -1;
		adjustReplicaRefresh("meta", numReplicas, refreshRateInSecs);
		adjustReplicaRefresh("vector", numReplicas, refreshRateInSecs);
		adjustReplicaRefresh("executable", numReplicas, refreshRateInSecs);
		response.success = true;
	}

	/**
	 * Entry point for the Elasticsearch version of PrewarmRequest command:
	 *   This interface currently does not support prewarm
	 * @param request is command parameters
	 */
	private void fdbPrewarm(PrewarmRequest request) {
		final ResponsePrewarm response = request.prewarmresponse;
		response.operationSupported = false;
	}

	/**
	 * Entry point for the Elasticsearch version of InsertRequest command:
	 *   Insert new functions and executables into the database.
	 * @param query is command parameters
	 * @throws LSHException if the command is misconfigured
	 * @throws ElasticException for communication problems with the server
	 * @throws DatabaseNonFatalException if everything is already inserted
	 */
	private void fdbDatabaseInsert(InsertRequest query)
			throws LSHException, ElasticException, DatabaseNonFatalException {
		if (info.readonly) {
			throw new LSHException("Trying to insert on read-only database");
		}
		if (FunctionDatabase.checkSettingsForInsert(query.manage, info)) { // Check if settings are valid and is this is first insert
			info.major = query.manage.getMajorVersion();
			info.minor = query.manage.getMinorVersion();
			info.settings = query.manage.getSettings();
			writeBasicInfo(0, 0); // Save off the settings associated with this first insert
		}
		ResponseInsert response = query.insertresponse;
		if ((query.repo_override != null) && (query.repo_override.length() != 0)) {
			query.manage.overrideRepository(query.repo_override, query.path_override);
		}
		// Insert each executable in turn
		boolean newExecutable = false;
		for (ExecutableRecord erec : query.manage.getExecutableRecordSet()) {
			if (erec.isLibrary()) {
				insertLibrary(query.manage, erec);
			}
			else if (insertExe(query.manage, erec)) {
				newExecutable = true;
			}
		}
		if (!newExecutable) {
			throw new DatabaseNonFatalException("Already inserted");
		}
		response.numexe = query.manage.getExecutableRecordSet().size();
		response.numfunc = query.manage.numFunctions();
	}

	/**
	 * Entry point for the Elasticsearch version of QueryPair command:
	 *   Query for pairs functions in the database, and compute the similarity
	 *   and significance of their feature vectors
	 * @param query is command parameters
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems adding records to the response
	 */
	private void fdbQueryPair(QueryPair query) throws ElasticException, LSHException {
		ResponsePair response = query.pairResponse;

		double aveSim = 0.0;
		double aveSimSquare = 0.0;
		double aveSig = 0.0;
		double aveSigSquare = 0.0;
		int pairCount = 0;
		int missedExe = 0;
		int missedFunc = 0;
		int missedVector = 0;

		List<FunctionDescription> aFuncList = new ArrayList<>();
		List<FunctionDescription> bFuncList = new ArrayList<>();
		DescriptionManager resManage = new DescriptionManager();
		TreeMap<ExeSpecifier, ExecutableRecord> nameMap = new TreeMap<>();
		for (PairInput pairInput : query.pairs) {
			FunctionDescription funcA = null;
			FunctionDescription funcB = null;
			ExecutableRecord erec = findSingleExeWithMap(pairInput.execA, resManage, nameMap);
			if (erec == null) {
				missedExe += 1;
			}
			else {
				funcA = queryByNameAddress(resManage, erec, pairInput.funcA.funcName,
					pairInput.funcA.address, true);
				if (funcA == null) {
					missedFunc += 1;
				}
			}

			erec = findSingleExeWithMap(pairInput.execB, resManage, nameMap);
			if (erec == null) {
				missedExe += 1;
			}
			else {
				funcB = queryByNameAddress(resManage, erec, pairInput.funcB.funcName,
					pairInput.funcB.address, true);
				if (funcB == null) {
					missedFunc += 1;
				}
			}
			aFuncList.add(funcA);
			bFuncList.add(funcB);
		}

		Iterator<FunctionDescription> bIter = bFuncList.iterator();
		VectorCompare vectorData = new VectorCompare();
		for (FunctionDescription funcA : aFuncList) {
			FunctionDescription funcB = bIter.next();
			if (funcA == null || funcB == null) {
				continue;
			}
			SignatureRecord sigA = funcA.getSignatureRecord();
			if (sigA == null) {
				missedVector += 1;
				continue;
			}
			SignatureRecord sigB = funcB.getSignatureRecord();
			if (sigB == null) {
				missedVector += 1;
				continue;
			}
			double sim = sigA.getLSHVector().compare(sigB.getLSHVector(), vectorData);
			double signif = vectorFactory.calculateSignificance(vectorData);
			PairNote pairNote = new PairNote(funcA, funcB, sim, signif, vectorData.dotproduct,
				vectorData.acount, vectorData.bcount, vectorData.intersectcount);
			response.notes.add(pairNote);
			pairCount += 1;
			aveSim += sim;
			aveSimSquare += sim * sim;
			aveSig += signif;
			aveSigSquare += signif * signif;
		}
		response.averageSim = aveSim / pairCount;
		response.averageSig = aveSig / pairCount;
		double simVariance = (aveSimSquare / pairCount) - response.averageSim * response.averageSim;
		response.simStdDev = Math.sqrt(simVariance);
		double sigVariance = (aveSigSquare / pairCount) - response.averageSig * response.averageSig;
		response.sigStdDev = Math.sqrt(sigVariance);
		response.scale = vectorFactory.getSignificanceScale();
		response.pairCount = pairCount;
		response.missedExe = missedExe;
		response.missedFunc = missedFunc;
		response.missedVector = missedVector;
	}

	/**
	 * Entry point for the Elasticsearch version of QueryNearest command:
	 *   Query for functions that are similar to those in the request.
	 * @param query is command parameters
	 * @throws LSHException for problems adding new records to the response
	 * @throws ElasticException for communication problems with the server
	 */
	private void fdbQueryNearest(QueryNearest query) throws LSHException, ElasticException {
		FunctionDatabase.checkSettingsForQuery(query.manage, info);
		String filter = null;
		if (query.bsimFilter != null) {
			ExecutableRecord repexe = query.manage.getExecutableRecordSet().first();
			IDElasticResolution idres[] = new IDElasticResolution[query.bsimFilter.numAtoms()];
			for (int i = 0; i < idres.length; ++i) {
				FilterAtom atom = query.bsimFilter.getAtom(i);
				idres[i] = atom.type.generateIDElasticResolution(atom);
				if (idres[i] != null) {
					idres[i].resolve(this, repexe);
				}
			}
			filter = ElasticEffects.createFilter(query.bsimFilter, idres);
		}
		final ResponseNearest response = query.nearresponse;
		response.totalfunc = 0;
		response.totalmatch = 0;
		response.uniquematch = 0;

		final DescriptionManager descMgr = new DescriptionManager();
		final Iterator<FunctionDescription> iter = query.manage.listAllFunctions();

		queryFunctions(query, filter, response, descMgr, iter);
		response.manage.transferSettings(query.manage); // Echo back the settings
	}

	/**
	 * Entry point for the Elasticsearch version of QueryNearestVector command:
	 *   Query for vectors that are similar to those in the request
	 * @param query is command parameters
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException if the command is misconfigured
	 */
	private void fdbQueryNearestVector(QueryNearestVector query)
			throws ElasticException, LSHException {
		FunctionDatabase.checkSettingsForQuery(query.manage, info);
		final ResponseNearestVector response = query.nearresponse;
		response.totalvec = 0;
		response.totalmatch = 0;
		response.uniquematch = 0;

		int vectormax = query.vectormax;
		if (vectormax == 0) {
			vectormax = MAX_VECTOR_OVERALL; // Really means a very big limit
		}

		final Iterator<FunctionDescription> iter = query.manage.listAllFunctions();
		while (iter.hasNext()) {
			final FunctionDescription frec = iter.next();
			final SignatureRecord srec = frec.getSignatureRecord();
			if (srec == null) {
				continue;
			}
			final LSHVector thevec = srec.getLSHVector();
			final double len2 = vectorFactory.getSelfSignificance(thevec);
			if (len2 < query.signifthresh) {
				continue;
			}

			response.totalvec += 1;
			final List<VectorResult> resultset = new ArrayList<>();

			queryNearestVector(resultset, thevec, query.thresh, query.signifthresh, vectormax);
			if (resultset.isEmpty()) {
				continue;
			}
			final SimilarityVectorResult simres = new SimilarityVectorResult(frec);
			simres.addNotes(resultset);
			response.totalmatch += simres.getTotalCount();
			if (simres.getTotalCount() == 1) {
				response.uniquematch += 1;
			}
			response.result.add(simres);
		}
	}

	private void fdbQueryVectorId(QueryVectorId query) throws ElasticException {
		List<VectorResult> resultList = query.vectorIdResponse.vectorResults;
		for (Long id : query.vectorIds) {
			VectorResult vecRes = new VectorResult();
			vecRes.vectorid = id;
			resultList.add(vecRes);
		}
		Iterator<VectorResult> iter1 = resultList.iterator();
		Iterator<VectorResult> iter2 = resultList.iterator();
		while (iter1.hasNext()) {
			fetchVectors(iter1, iter2, 50);						// Fetch vector associated with each vectorid
		}
		iter1 = resultList.iterator();
		iter2 = resultList.iterator();
		while (iter1.hasNext()) {
			fetchVectorCounts(iter1, iter2, MAX_VECTORCOUNT_WINDOW);	// Fetch hitcount of each vector
		}
	}

	private void fdbQueryVectorMatch(QueryVectorMatch query) throws ElasticException, LSHException {
		String filter = null;
		if (query.bsimFilter != null) {
			ExecutableRecord repexe = null;		// Needed for ExternalFunction filter
			IDElasticResolution idres[] = new IDElasticResolution[query.bsimFilter.numAtoms()];
			for (int i = 0; i < idres.length; ++i) {
				FilterAtom atom = query.bsimFilter.getAtom(i);
				idres[i] = atom.type.generateIDElasticResolution(atom);
				if (idres[i] != null) {
					idres[i].resolve(this, repexe);
				}
			}
			filter = ElasticEffects.createFilter(query.bsimFilter, idres);
		}
		List<VectorResult> vectorList = new ArrayList<>();
		for (Long id : query.vectorIds) {
			VectorResult vecRes = new VectorResult();
			vecRes.vectorid = id;
			vectorList.add(vecRes);
		}
		Iterator<VectorResult> iter1 = vectorList.iterator();
		Iterator<VectorResult> iter2 = vectorList.iterator();
		while (iter1.hasNext()) {
			fetchVectors(iter1, iter2, 50);						// Fetch vector associated with each vectorid
		}
		iter1 = vectorList.iterator();
		iter2 = vectorList.iterator();
		while (iter1.hasNext()) {
			fetchVectorCounts(iter1, iter2, MAX_VECTORCOUNT_WINDOW);	// Fetch hitcount of each vector
		}
		int count = 0;
		DescriptionManager manager = query.matchresponse.manage;
		for (VectorResult vecResult : vectorList) {
			if (count >= query.max) {
				break;
			}
			SignatureRecord srec = manager.newSignature(vecResult.vec, vecResult.hitcount);
			JSONArray descres;
			descres = queryVectorIdMatch(vecResult.vectorid, filter, query.max - count);
			if (descres == null) {
				throw new ElasticException(
					"Error querying vectorid: " + Long.toString(vecResult.vectorid));
			}
			if (descres.size() == 0) {
				if (filter != null) {
					continue; // Filter may have eliminated all results
				}
				// Otherwise this is a sign of corruption in the database
				throw new ElasticException(
					"No functions matching vectorid: " + Long.toString(vecResult.vectorid));
			}
			count += descres.size();
			convertDescriptionRows(null, descres, vecResult, manager, srec);
		}
	}

	/**
	 * Entry point for the Elasticsearch version of QueryDelete command:
	 *   Delete specific executables from the database
	 * @param query is command parameters
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems building records
	 */
	private void fdbDelete(QueryDelete query) throws ElasticException, LSHException {
		final ResponseDelete response = query.respdelete;
		for (ExeSpecifier spec : query.exelist) {
			DescriptionManager manager = new DescriptionManager();
			ExecutableRecord erec = null;
			if (spec.exemd5.length() != 0) {
				JSONObject row = queryMd5ExeMatch(spec.exemd5);
				if (row != null) {
					erec = makeExecutableRecord(manager, row);
				}
			}
			else {
				erec = querySingleExecutable(manager, spec.exename, spec.arch, spec.execompname);
			}
			if (erec == null) {
				response.missedlist.add(spec);
				continue;
			}
			ResponseDelete.DeleteResult delrec = new ResponseDelete.DeleteResult();
			delrec.md5 = erec.getMd5();
			delrec.name = erec.getNameExec();
			List<FunctionDescription> funclist = new ArrayList<>();
			RowKeyElastic eKey = updateKey(manager, erec);
			String exeId = eKey.generateExeIdString();
			queryAllFunc(funclist, erec, exeId, manager, 0);
			Set<IdHistogram> table = IdHistogram.buildVectorIdHistogram(funclist.iterator());
			List<IdHistogram> deleteList = new ArrayList<>();
			Iterator<IdHistogram> iter1 = table.iterator();
			Iterator<IdHistogram> iter2 = table.iterator();
			while (iter1.hasNext()) {
				decrementVectorCounters(deleteList, iter1, iter2, MAX_VECTORDELETE_WINDOW);
			}
			iter1 = deleteList.iterator();
			while (iter1.hasNext()) {
				deleteRawVectors(iter1, MAX_VECTORDELETE_WINDOW);
			}

			delrec.funccount = deleteExeDocuments(exeId);
			response.reslist.add(delrec);
		}
	}

	/**
	 * Entry point for the Elasticsearch version of QueryUpdate command:
	 *   Update meta-data about specific executables and functions within the database
	 * @param query is command parameters
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems grouping records
	 */
	private void fdbUpdate(QueryUpdate query) throws ElasticException, LSHException {
		ResponseUpdate response = query.updateresponse;
		for (ExecutableRecord erec : query.manage.getExecutableRecordSet()) {
			int res = updateExecutable(query.manage, erec, response.badfunc);
			if (res < 0) {
				response.badexe.add(erec);
			}
			else {
				if ((res & 1) != 0) {
					response.exeupdate += 1;
				}
				response.funcupdate += res >> 1;
			}
		}
	}

	/**
	 * Entry point for the Elasticsearch version of PasswordChange command.
	 * @param query is command parameters
	 * @throws LSHException if details of the request are malformed
	 */
	private void fdbPasswordChange(PasswordChange query) throws LSHException {
		ResponsePassword response = query.passwordResponse;
		if (query.username == null) {
			throw new LSHException("Missing username for password change");
		}
		if (query.newPassword == null || query.newPassword.length == 0) {
			throw new LSHException("No password provided");
		}
		response.changeSuccessful = true;		// Response parameters assuming success
		response.errorMessage = null;
		try {
			changePasswordInternal(query.username, query.newPassword);
		}
		catch (ElasticException ex) {
			response.changeSuccessful = false;
			response.errorMessage = ex.getMessage();
		}
		query.clearPassword();
	}

	/**
	 * Given the document id for a specific function. Query for the document and
	 * produce the corresponding FunctionDescription
	 * @param manager is the container for the new FunctionDescription
	 * @param rowId is the document id of the function
	 * @return the new FunctionDescription
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems adding records to the container
	 */
	private FunctionDescription querySingleDescriptionId(DescriptionManager manager, String rowId)
			throws ElasticException, LSHException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{ \"query\": { \"ids\": { \"values\": [ \"");
		buffer.append(rowId);
		buffer.append("\" ] } } }");
		JSONObject resp = connection.executeStatement(ElasticConnection.GET, "executable/_search",
			buffer.toString());
		JSONObject hits = (JSONObject) resp.get("hits");
		JSONObject totalRec = (JSONObject) hits.get("total");
		long total = (Long) totalRec.get("value");
		if (total == 0) {
			throw new ElasticException("No function documents matching id=" + rowId);
		}
		JSONArray hitsArray = (JSONArray) hits.get("hits");
		JSONObject row = (JSONObject) hitsArray.get(0);
		JSONObject source = (JSONObject) row.get("_source");
		JSONObject joinfield = (JSONObject) source.get("join_field");
		String exeId = (String) joinfield.get("parent");
		RowKeyElastic eKey = RowKeyElastic.parseExeIdString(exeId);
		ExecutableRecord exeRec = manager.findExecutableByRow(eKey);
		if (exeRec == null) {
			List<RowKeyElastic> keyList = new ArrayList<>();
			keyList.add(eKey);
			queryExecutableRecordById(manager, keyList.iterator(), keyList.iterator(), 2);
			exeRec = manager.findExecutableByRow(eKey);
		}
		return convertDescriptionRow(row, exeRec, manager, null);
	}

	/**
	 * Given a specific function, query the database for the document ids of its children
	 * @param funcRecord is the specific function
	 * @return the child document ids as an array of JSON strings
	 * @throws ElasticException for communication problems with the server
	 */
	private JSONArray queryCallgraphRows(FunctionDescription funcRecord) throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("executable/_doc/");
		RowKeyElastic eKey = (RowKeyElastic) funcRecord.getExecutableRecord().getRowId();
		eKey.generateFunctionId(buffer, funcRecord);
		buffer.append("?routing=");
		buffer.append(eKey.generateExeIdString());
		buffer.append("&_source_includes=childid");
		JSONObject resp = connection.executeURIOnly(ElasticConnection.GET, buffer.toString());
		JSONObject source = (JSONObject) resp.get("_source");
		JSONArray childid = (JSONArray) source.get("childid");
		return childid;
	}

	/**
	 * Given a specific function, query for all of its child functions.
	 * Uses a RowKey->FunctionDescription map to cache functions and avoid
	 * querying for the same function multiple times
	 * @param funcRecord is the specified function
	 * @param manager is the container for new child FunctionDescriptions
	 * @param functionMap is the cache
	 * @throws ElasticException for communication problems with the server
	 * @throws LSHException for problems adding records to the container
	 */
	private void fillinChildren(FunctionDescription funcRecord, DescriptionManager manager,
			Map<RowKey, FunctionDescription> functionMap) throws ElasticException, LSHException {
		if (!info.trackcallgraph) {
			throw new ElasticException(
				"Elasticsearch database does not have callgraph information enabled");
		}
		JSONArray callids = queryCallgraphRows(funcRecord);
		if (callids == null) {
			return;		// field is not present, meaning children are not present
		}
		for (Object callid : callids) {
			String funcId = (String) callid;
			RowKeyElastic eKey = RowKeyElastic.parseFunctionId(funcId);
			FunctionDescription fdesc = functionMap.get(eKey);
			if (fdesc == null) {
				fdesc = querySingleDescriptionId(manager, funcId);
				functionMap.put(eKey, fdesc);
			}
			manager.makeCallgraphLink(funcRecord, fdesc, 0);
		}
	}

	/**
	 * Entry point for Elasticsearch version of the QueryChildren command:
	 *   Query for the child functins of submitted functions
	 * @param query is command parameters
	 * @throws LSHException for problems adding records to the response
	 * @throws ElasticException for communication problems with the server
	 */
	private void fdbQueryChildren(QueryChildren query) throws LSHException, ElasticException {
		if (!info.trackcallgraph) {
			throw new LSHException("Database does not track callgraph");
		}
		ResponseChildren response = query.childrenresponse;
		ExecutableRecord exe = null;

		ExeSpecifier exeSpec = new ExeSpecifier();
		exeSpec.exemd5 = query.md5sum;
		exeSpec.exename = query.name_exec;
		exeSpec.arch = query.arch;
		exeSpec.execompname = query.name_compiler;

		exe = findSingleExecutable(exeSpec, response.manage);
		if (exe == null) {
			throw new LSHException("Could not (uniquely) match executable");
		}
		for (FunctionEntry entry : query.functionKeys) {
			FunctionDescription func =
				queryByNameAddress(response.manage, exe, entry.funcName, entry.address, true);
			if (func == null) {
				throw new LSHException("Could not find function: " + entry.funcName);
			}
			response.correspond.add(func);
		}

		TreeMap<RowKey, FunctionDescription> funcmap = new TreeMap<>();
		response.manage.generateFunctionIdMap(funcmap);
		for (FunctionDescription element : response.correspond) {
			fillinChildren(element, response.manage, funcmap);
		}
	}

	/**
	 * Entry point for the Elasticsearch version of QueryInfo command:
	 *   Query for basic information about a database
	 * @param query is command parameters
	 */
	private void fdbDatabaseInfo(QueryInfo query) {
		final ResponseInfo response = query.inforesponse;
		response.info = info;
	}
}
