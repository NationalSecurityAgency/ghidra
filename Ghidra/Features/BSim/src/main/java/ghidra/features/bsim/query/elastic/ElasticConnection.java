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

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class ElasticConnection {
	public static final String POST = "POST";
	public static final String PUT = "PUT";
	public static final String GET = "GET";
	public static final String DELETE = "DELETE";

	protected String hostURL;				// http://hostname:port
	protected String httpURLbase;			// Main URL to elasticsearch
	private int lastResponseCode;

	public ElasticConnection(String url, String repo) {
		hostURL = url;
		httpURLbase = url + '/' + repo + '_';
	}

	public void close() {
		// nothing to do - http connections do not persist
	}

	public boolean lastRequestSuccessful() {
		return (lastResponseCode >= 200) && (lastResponseCode < 300);
	}

	/**
	 * Assuming the writer has been closed and connection.getResponseCode() is called
	 * placing the value in lastResponseCode, read the response and parse into a JSONObject
	 * @return the JSONObject
	 * @throws IOException for problems with the socket
	 * @throws ParseException for JSON parse errors
	 */
	private JSONObject grabResponse(HttpURLConnection connection)
			throws IOException, ParseException {
		JSONParser parser = new JSONParser();
		InputStream in;
		if (lastRequestSuccessful()) {
			in = connection.getInputStream();
		}
		else {
			in = connection.getErrorStream();
		}
		if (in == null) {
			// Connection error occurred
			throw new IOException(connection.getResponseMessage());
		}
		Reader reader = new InputStreamReader(in);
		JSONObject jsonObject = (JSONObject) parser.parse(reader);
		return jsonObject;
	}

	/**
	 * Elastic search sends a JSON document in the Http error stream for any error
	 * Pull out relevant info from the document and construct an exception message
	 * @param resp is the parsed error document
	 * @return the exception String
	 */
	private String parseErrorJSON(JSONObject resp) {
		Object errorObj = resp.get("error");
		if (errorObj == null) {
			return "Unknown error format";
		}
		if (errorObj instanceof String) {
			return (String) errorObj;
		}
		if (!(errorObj instanceof JSONObject)) {
			return "Unknown error format";
		}
		JSONObject jsonObj = (JSONObject) errorObj;
		String typeString = (String) jsonObj.get("type");
		String reasonString = (String) jsonObj.get("reason");
		if (typeString == null) {
			typeString = "Unknown Error";
		}
		if (reasonString == null) {
			reasonString = "Unknown reason";
		}
		return typeString + " : " + reasonString;
	}

	/**
	 * Send a raw request to the server that is not specific to the repository.
	 * Intended for general configuration or security commands
	 * @param command is the type of command
	 * @param path is the specific URL path receiving the command
	 * @param body is JSON document describing the command
	 * @return the response as parsed JSONObject
	 * @throws ElasticException for any problems with the connection
	 */
	public JSONObject executeRawStatement(String command, String path, String body)
			throws ElasticException {
		HttpURLConnection connection = null;
		try {
			URL httpURL = new URL(hostURL + path);
			connection = (HttpURLConnection) httpURL.openConnection();
			connection.setRequestMethod(command);
			connection.setRequestProperty("Content-Type", "application/json");
			connection.setDoOutput(true);
			try (Writer writer = new OutputStreamWriter(connection.getOutputStream())) {
				writer.write(body);
			}
			lastResponseCode = connection.getResponseCode();
			JSONObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (ParseException e) {
			throw new ElasticException("Error parsing response: " + e.getMessage());
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}

	}

	/**
	 * Execute an elasticsearch command where we are not expecting a response
	 * @param command is the type of the command
	 * @param path is the overarching index/type/<command>
	 * @param body is the JSON document describing the request
	 * @throws ElasticException for any problems with the connecting
	 */
	public void executeStatementNoResponse(String command, String path, String body)
			throws ElasticException {
		HttpURLConnection connection = null;
		try {
			URL httpURL = new URL(httpURLbase + path);
			connection = (HttpURLConnection) httpURL.openConnection();
			connection.setRequestMethod(command);
			connection.setRequestProperty("Content-Type", "application/json");
			connection.setDoOutput(true);
			try (Writer writer = new OutputStreamWriter(connection.getOutputStream())) {
				writer.write(body);
			}
			lastResponseCode = connection.getResponseCode();
			JSONObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (ParseException e) {
			throw new ElasticException("Error parsing response: " + e.getMessage());
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	/**
	 * Execute an elastic search statement and return the JSON response to user
	 * @param command is the type of command
	 * @param path is the overarching index/type/<command>
	 * @param body is JSON document describing the request
	 * @return the parsed response as a JSONObject
	 * @throws ElasticException for any problems with the connection
	 */
	public JSONObject executeStatement(String command, String path, String body)
			throws ElasticException {
		HttpURLConnection connection = null;
		try {
			URL httpURL = new URL(httpURLbase + path);
			connection = (HttpURLConnection) httpURL.openConnection();
			connection.setRequestMethod(command);
			connection.setRequestProperty("Content-Type", "application/json");
			connection.setDoOutput(true);
			try (Writer writer = new OutputStreamWriter(connection.getOutputStream())) {
				writer.write(body);
			}
			lastResponseCode = connection.getResponseCode();
			JSONObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (ParseException e) {
			throw new ElasticException("Error parsing response: " + e.getMessage());
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	/**
	 * Execute an elastic search statement and return the JSON response to user
	 * Do not throw an exception on failure, just return the error response
	 * @param command is the type of command
	 * @param path is the overarching index/type/<command>
	 * @param body is JSON document describing the request
	 * @return the parsed response as a JSONObject
	 * @throws ElasticException for any problems with the connection
	 */
	public JSONObject executeStatementExpectFailure(String command, String path, String body)
			throws ElasticException {
		HttpURLConnection connection = null;
		try {
			URL httpURL = new URL(httpURLbase + path);
			connection = (HttpURLConnection) httpURL.openConnection();
			connection.setRequestMethod(command);
			connection.setRequestProperty("Content-Type", "application/json");
			connection.setDoOutput(true);
			try (Writer writer = new OutputStreamWriter(connection.getOutputStream())) {
				writer.write(body);
			}
			lastResponseCode = connection.getResponseCode();
			JSONObject resp = grabResponse(connection);
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (ParseException e) {
			throw new ElasticException("Error parsing response: " + e.getMessage());
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	/**
	 * Send a bulk request to the elasticsearch server.  This is a special format for combining multiple commands
	 * and is structured slightly differently from other commands.
	 * @param path is the specific URL path receiving the bulk command
	 * @param body is structured list of JSON commands and source
	 * @return the response as parsed JSONObject
	 * @throws ElasticException for any problems with the connection
	 */
	public JSONObject executeBulk(String path, String body) throws ElasticException {
		HttpURLConnection connection = null;
		try {
			URL httpURL = new URL(hostURL + path);
			connection = (HttpURLConnection) httpURL.openConnection();
			connection.setRequestMethod(POST);
			connection.setRequestProperty("Content-Type", "application/x-ndjson");
			connection.setDoOutput(true);
			try (Writer writer = new OutputStreamWriter(connection.getOutputStream())) {
				writer.write(body);
			}
			lastResponseCode = connection.getResponseCode();
			JSONObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (ParseException e) {
			throw new ElasticException("Error parsing response: " + e.getMessage());
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	public JSONObject executeURIOnly(String command, String path) throws ElasticException {
		HttpURLConnection connection = null;
		try {
			URL httpURL = new URL(httpURLbase + path);
			connection = (HttpURLConnection) httpURL.openConnection();
			connection.setRequestMethod(command);
			connection.setDoOutput(true);
			lastResponseCode = connection.getResponseCode();
			JSONObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (ParseException e) {
			throw new ElasticException("Error parsing response: " + e.getMessage());
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}
}
