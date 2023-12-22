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
package ghidra.features.bsim.query.client;

import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.net.*;

import org.xml.sax.*;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.protocol.*;
import ghidra.framework.client.ClientUtil;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

public class FunctionDatabaseProxy implements FunctionDatabase {
	private DatabaseInformation info;
	private LSHVectorFactory vectorFactory;
	private URL httpURL;
	private Error lasterror;
	private Status status;
	private boolean isinit;
	private XmlErrorHandler xmlErrorHandler;

	static class XmlErrorHandler implements ErrorHandler {

		@Override
		public void warning(SAXParseException exception) throws SAXException {
			// Ignore warnings
		}

		@Override
		public void error(SAXParseException exception) throws SAXException {
			throw exception;
		}

		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			throw exception;
		}

	}

	public FunctionDatabaseProxy(URL url) throws MalformedURLException {
		httpURL = new URL(url.toString());		// Make sure URL has a real handler
		lasterror = null;
		info = null;
		vectorFactory = FunctionDatabase.generateLSHVectorFactory();
		status = Status.Unconnected;
		isinit = false;
		xmlErrorHandler = new XmlErrorHandler();
	}

	@Override
	public Status getStatus() {
		return status;
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
		// Not currently implemented
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
		if (info.layout_version == PostgresFunctionDatabase.LAYOUT_VERSION) {
			return 0;
		}
		return (info.layout_version < PostgresFunctionDatabase.LAYOUT_VERSION) ? -1 : 1;
	}

	@Override
	public String getURLString() {
		return httpURL.toString();
	}

	@Override
	public BSimServerInfo getServerInfo() {
		return new BSimServerInfo(httpURL);
	}

	@Override
	public boolean initialize() {
		if (isinit) {
			return true;
		}
		if (httpURL == null) {
			status = Status.Error;
			lasterror = new FunctionDatabase.Error(ErrorCategory.Initialization, "MalformedURL");
			return false;
		}
		QueryInfo queryInfo = new QueryInfo();
		QueryResponseRecord response = query(queryInfo);
		if (response == null) {
			return false;
		}
		info = ((ResponseInfo) response).info;
		status = Status.Ready;
		isinit = true;
		return true;
	}

	@Override
	public void close() {
		status = Status.Unconnected;
		isinit = false;
		info = null;
	}

	@Override
	public Error getLastError() {
		return lasterror;
	}

	@Override
	public QueryResponseRecord query(BSimQuery<?> query) {
		HttpURLConnection connection;
		query.buildResponseTemplate();
		try {
			lasterror = null;
			connection = (HttpURLConnection) httpURL.openConnection();
			connection.setRequestMethod("POST");
			connection.setDoOutput(true);
			BufferedWriter writer =
				new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));
			query.saveXml(writer);
			writer.close();
			XmlPullParser parser = new NonThreadedXmlPullParserImpl(connection.getInputStream(),
				"response", xmlErrorHandler, false);
			if (parser.peek().getName().equals("error")) {
				ResponseError respError = new ResponseError();
				respError.restoreXml(parser, vectorFactory);
				parser.dispose();
				lasterror = new FunctionDatabase.Error(ErrorCategory.Fatal, respError.errorMessage);
				query.clearResponse();
				return null;
			}
			QueryResponseRecord response = query.getResponse();
			response.restoreXml(parser, vectorFactory);
			parser.dispose();
			if (response instanceof ResponseInfo) {
				// Query is one of CreateDatabase, InstallCategoryRequest, InstallMetadataRequest, or QueryInfo
				info = ((ResponseInfo) response).info;
				status = Status.Ready;
				isinit = true;
			}
			return response;
		}
		catch (Exception ex) {
			lasterror = new FunctionDatabase.Error(ErrorCategory.Connection, ex.getMessage());
			status = Status.Error;
			query.clearResponse();
			return null;
		}
	}

}
