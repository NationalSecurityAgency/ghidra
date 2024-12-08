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
package ghidra.features.bsim.query.facade;

import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;

import generic.jar.ResourceFile;
import generic.lsh.vector.LSHVectorFactory;
import generic.lsh.vector.WeightedLSHCosineVectorFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.SQLFunctionDatabase;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.protocol.BSimQuery;
import ghidra.features.bsim.query.protocol.QueryResponseRecord;
import ghidra.framework.Application;
import ghidra.framework.client.ClientUtil;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

public class FunctionDatabaseTestDouble implements SQLFunctionDatabase {
	private static final String TEST_URL = "ghidra://localhost/db";

	private Status status = Status.Ready;
	private final String urlString;
	private boolean canInitialize;
	private String errorString;
	private QueryResponseRecord record;
	private static LSHVectorFactory vectorFactory = null;

	private BSimQuery<?> lastQuery;

	public FunctionDatabaseTestDouble() {
		this(TEST_URL);
	}

	public FunctionDatabaseTestDouble(String urlString) {
		this.urlString = urlString;
		if (vectorFactory == null) {
			vectorFactory = new WeightedLSHCosineVectorFactory();
			loadWeightsFile(vectorFactory);
		}
	}

	public static void loadWeightsFile(LSHVectorFactory factory) {
		ResourceFile weightsFile = Application.findDataFileInAnyModule("lshweights_32.xml");
		try {
			InputStream input = weightsFile.getInputStream();
			XmlPullParser parser = new NonThreadedXmlPullParserImpl(input, "Vector weights parser",
				SpecXmlUtils.getXmlHandler(), false);
			factory.readWeights(parser);
			input.close();
		}
		catch (Exception ex) {
			// If weights aren't available, tests will fail reading settings
		}
	}

	@Override
	public QueryResponseRecord query(BSimQuery<?> query) {
		this.status = Status.Busy;
		this.lastQuery = query;
		this.status = Status.Ready;
		return record;
	}

	BSimQuery<?> getLastQuery() {
		return lastQuery;
	}

	public void setQueryResponse(QueryResponseRecord record) {
		this.record = record;
	}

	@Override
	public Status getStatus() {
		return status;
	}

	void setStatus(Status status) {
		this.status = status;
	}

	@Override
	public ConnectionType getConnectionType() {
		return ConnectionType.Unencrypted_No_Authentication;
	}

	@Override
	public String getUserName() {
		return ClientUtil.getUserName();
	}

	@Override
	public void setUserName(String userName) {
		// Currently not implemented
	}

	@Override
	public String getURLString() {
		return urlString;
	}

	@Override
	public BSimServerInfo getServerInfo() {
		try {
			return new BSimServerInfo(new URL(urlString));
		}
		catch (IllegalArgumentException | MalformedURLException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public boolean initialize() {
		return canInitialize;
	}

	public void setCanInitialize(boolean canInitialize) {
		this.canInitialize = canInitialize;
	}

	@Override
	public void close() {
		// nothing to do
	}

	@Override
	public Error getLastError() {
		return new Error(ErrorCategory.Unused, errorString);
	}

	void setErrorString(String errorString) {
		this.errorString = errorString;
	}

	@Override
	public DatabaseInformation getInfo() {
		return new DatabaseInformation();
	}

	@Override
	public int compareLayout() {
		return 0;
	}

	@Override
	public LSHVectorFactory getLSHVectorFactory() {
		return vectorFactory;
	}

	@Override
	public String formatBitAndSQL(String v1, String v2) {
		return "(" + v1 + " & " + v2 + ")"; // copied from postgress
	}

}
