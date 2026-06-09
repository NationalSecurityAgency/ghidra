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

import com.google.gson.*;

import ghidra.util.Msg;

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

	public boolean lastRequestSuccessful() {
		return (lastResponseCode >= 200) && (lastResponseCode < 300);
	}

	/**
	 * Get String held by a JsonElement, allowing for a null object.
	 * @param element is the JsonElement or null
	 * @return the underlying String or null
	 */
	static String convertToString(JsonElement element) {
		if (isNull(element)) {
			return null;
		}
		return element.getAsString();
	}

	/**
	 * Get String held by a JsonElement, allowing for a null object.
	 * @param element is the JsonElement or null
	 * @param defaultStr default string to be returned if element or string is null
	 * @return the underlying String or defaultStr if null
	 */
	static String convertToString(JsonElement element, String defaultStr) {
		String str = convertToString(element);
		return str != null ? str : defaultStr;
	}

	/**
	 * Check element for null value
	 * @param element json element
	 * @return true if null else false
	 */
	static boolean isNull(JsonElement element) {
		return (element == null || element instanceof JsonNull);
	}

	/**
	 * Assuming the writer has been closed and connection.getResponseCode() is called
	 * placing the value in lastResponseCode, read the response and parse into a JsonObject
	 * @return the JsonObject
	 * @throws IOException for problems with the socket
	 * @throws JsonParseException for JSON parse errors
	 */
	private JsonObject grabResponse(HttpURLConnection connection)
			throws IOException, JsonParseException {
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
		JsonObject jsonObject = JsonParser.parseReader(reader).getAsJsonObject();
		return jsonObject;
	}

	/**
	 * Elastic search sends a JSON document in the Http error stream for any error
	 * Pull out relevant info from the document and construct an exception message
	 * @param resp is the parsed error document
	 * @return the exception String
	 */
	private static String parseErrorJSON(JsonObject resp) {
		Object errorObj = resp.get("error");
		if (errorObj instanceof String) {
			return (String) errorObj;
		}
		if (!(errorObj instanceof JsonObject err)) {
			return "Unknown error format";
		}

		String typeString = convertToString(err.get("type"), "Unknown Error");
		if (typeString.endsWith("_exception")) {
			// Log elastic exception root cause to assist debug
			String errorDetail = parseErrorCause(err);
			if (errorDetail.length() != 0) {
				Msg.error(ElasticConnection.class, "Elasticsearch exception: " + errorDetail);
			}
		}

		String reasonString = convertToString(err.get("reason"), "Unknown Reason");
		return typeString + " : " + reasonString;
	}

	private static StringBuilder conditionalNewLine(StringBuilder buf) {
		if (!buf.isEmpty()) {
			buf.append("\n");
		}
		return buf;
	}

	private static String parseErrorCause(JsonObject error) {

		StringBuilder buf = new StringBuilder();

		JsonElement reason = error.get("reason");

		String typeString = convertToString(error.get("type"));
		if (typeString != null) {
			String reasonString = convertToString(reason); // "reason" is string when "type" is present
			String errorStr = typeString + " : " + reasonString;
			conditionalNewLine(buf).append(errorStr);
		}

		JsonElement scriptStack = error.get("script_stack");
		if (scriptStack instanceof JsonArray scriptStackArray) {
			scriptStackArray
					.forEach(e -> conditionalNewLine(buf).append("   ").append(convertToString(e)));
		}

		JsonElement causedBy = error.get("caused_by");
		if (causedBy instanceof JsonObject causedByObject) {
			conditionalNewLine(buf).append("   ").append(parseErrorCause(causedByObject));
		}

		JsonElement failedShards = error.get("failed_shards");
		if (failedShards instanceof JsonArray failedShardsArray) {
			for (JsonElement failedShardElement : failedShardsArray) {
				JsonObject failedShard = (JsonObject) failedShardElement;
				String indexStr = convertToString(failedShard.get("index"));
				conditionalNewLine(buf).append("   Failed shard index: ").append(indexStr);
				conditionalNewLine(buf).append("   ").append(parseErrorCause(failedShard));
			}
		}

		if (reason instanceof JsonObject reasonObject) {
			conditionalNewLine(buf).append(parseErrorCause(reasonObject));
		}

		return buf.toString();
	}

	/**
	 * Send a raw request to the server that is not specific to the repository.
	 * Intended for general configuration or security commands
	 * @param command is the type of command
	 * @param path is the specific URL path receiving the command
	 * @param body is JSON document describing the command
	 * @return the response as parsed JsonObject
	 * @throws ElasticException for any problems with the connection
	 */
	public JsonObject executeRawStatement(String command, String path, String body)
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
			JsonObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (JsonParseException e) {
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
	 * @param path is the overarching {@code index/type/<command>}
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
			JsonObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (JsonParseException e) {
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
	 * @param path is the overarching {@code index/type/<command>}
	 * @param body is JSON document describing the request
	 * @return the parsed response as a JsonObject
	 * @throws ElasticException for any problems with the connection
	 */
	public JsonObject executeStatement(String command, String path, String body)
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
			JsonObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (JsonParseException e) {
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
	 * @param path is the overarching {@code index/type/<command>}
	 * @param body is JSON document describing the request
	 * @return the parsed response as a JsonObject
	 * @throws ElasticException for any problems with the connection
	 */
	public JsonObject executeStatementExpectFailure(String command, String path, String body)
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
			JsonObject resp = grabResponse(connection);
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (JsonParseException e) {
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
	 * @return the response as parsed JsonObject
	 * @throws ElasticException for any problems with the connection
	 */
	public JsonObject executeBulk(String path, String body) throws ElasticException {
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
			JsonObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (JsonParseException e) {
			throw new ElasticException("Error parsing response: " + e.getMessage());
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	public JsonObject executeURIOnly(String command, String path) throws ElasticException {
		HttpURLConnection connection = null;
		try {
			URL httpURL = new URL(httpURLbase + path);
			connection = (HttpURLConnection) httpURL.openConnection();
			connection.setRequestMethod(command);
			connection.setDoOutput(true);
			lastResponseCode = connection.getResponseCode();
			JsonObject resp = grabResponse(connection);
			if (!lastRequestSuccessful()) {
				throw new ElasticException(parseErrorJSON(resp));
			}
			return resp;
		}
		catch (IOException e) {
			throw new ElasticException("Error sending request: " + e.getMessage());
		}
		catch (JsonParseException e) {
			throw new ElasticException("Error parsing response: " + e.getMessage());
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}
}
