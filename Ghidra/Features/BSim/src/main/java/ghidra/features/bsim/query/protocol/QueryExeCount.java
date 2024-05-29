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
 * Query for counting the number of executable records in the database.
 * <p>
 * This contains all the information required to get a list of all executables in the
 * BSim database that meet a set of filter criteria. The results are stored in the
 * {@link #exeresponse} object.
 */
public class QueryExeCount extends BSimQuery<ResponseExe> {

	public ResponseExe exeresponse = null;
	public String filterMd5;
	public String filterExeName;
	public String filterArch;
	public String filterCompilerName;
	public boolean includeFakes;

	/**
	 * Query for count of all executables not including libraries
	 */
	public QueryExeCount() {
		super("queryexecount");
		this.filterMd5 = null;
		this.filterExeName = null;
		this.filterArch = null;
		this.filterCompilerName = null;
		this.includeFakes = false;
	}

	/**
	 * Constructor
	 * 
	 * @param filterMd5 md5 filter
	 * @param filterExeName executable name filter
	 * @param filterArch architecture filter
	 * @param filterCompilerName compiler name filter
	 * @param includeFakes if true, include MD5s that start with <code>bbbbbbbbaaaaaaa</code>
	 */
	public QueryExeCount(String filterMd5, String filterExeName, String filterArch,
			String filterCompilerName, boolean includeFakes) {
		super("queryexecount");
		this.filterMd5 = filterMd5;
		this.filterExeName = filterExeName;
		this.filterArch = filterArch;
		this.filterCompilerName = filterCompilerName;
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
