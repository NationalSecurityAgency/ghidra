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
import ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn;
import ghidra.xml.XmlPullParser;

/**
 * Query of executable records
 */
public class QueryExeInfo extends BSimQuery<ResponseExe> {

	public ResponseExe exeresponse = null;
	public int limit;
	public String filterMd5;
	public String filterExeName;
	public String filterArch;
	public String filterCompilerName;
	public ExeTableOrderColumn sortColumn;
	public boolean includeFakes;
	public boolean fillinCategories;

	/**
	 * Default query for the first 20 executables in the database
	 */
	public QueryExeInfo() {
		super("queryexeinfo");
		this.limit = 20;
		this.filterMd5 = null;
		this.filterExeName = null;
		this.filterArch = null;
		this.filterCompilerName = null;
		this.sortColumn = ExeTableOrderColumn.MD5;
		this.includeFakes = false;
		this.fillinCategories = true;
	}

	/**
	 * Constructor
	 * 
	 * @param limit the max number of results to return
	 * @param filterMd5 md5 the md5 filter
	 * @param filterExeName the exe filter
	 * @param filterArch the architecture filter
	 * @param filterCompilerName the compiler name filter
	 * @param sortColumn the primary sort column name
	 * @param includeFakes if false, will exclude generated MD5s starting with "bbbbbbbbaaaaaaaa"
	 */
	public QueryExeInfo(int limit, String filterMd5, String filterExeName, String filterArch,
			String filterCompilerName, ExeTableOrderColumn sortColumn, boolean includeFakes) {
		super("queryexeinfo");
		this.limit = limit;
		this.filterMd5 = filterMd5;
		this.filterExeName = filterExeName;
		this.filterArch = filterArch;
		this.filterCompilerName = filterCompilerName;
		this.sortColumn = sortColumn;
		this.includeFakes = includeFakes;
	}
	
	@Override
	public void buildResponseTemplate() {
		if (response == null) {
			response = exeresponse = new ResponseExe();
		}
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		// no need to implement
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		// no need to implement
	}
}
