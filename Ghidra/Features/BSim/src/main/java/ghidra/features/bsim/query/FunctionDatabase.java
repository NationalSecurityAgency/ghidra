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
package ghidra.features.bsim.query;

import java.io.*;
import java.util.*;

import javax.xml.parsers.*;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import generic.lsh.vector.LSHVectorFactory;
import generic.lsh.vector.WeightedLSHCosineVectorFactory;
import ghidra.features.bsim.query.client.Configuration;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.facade.SFOverviewInfo;
import ghidra.features.bsim.query.facade.SFQueryInfo;
import ghidra.features.bsim.query.protocol.*;
import ghidra.framework.Application;
import ghidra.util.Msg;

public interface FunctionDatabase extends AutoCloseable {

	public enum Status {
		Unconnected("Unconnected"), Busy("Busy"), Error("Error"), Ready("Ready");

		private final String label;

		private Status(String label) {
			this.label = label;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	public enum ConnectionType {
		// TODO: Should we add Never_Connected ?
		SSL_No_Authentication(0), SSL_Password_Authentication(1), Unencrypted_No_Authentication(2);

		private ConnectionType(int label) {
			// label is currently unused
		}
	}

	public enum ErrorCategory {
		Unused(0),
		Nonfatal(1),
		Fatal(2),
		Initialization(3),
		Format(4),
		Nodatabase(5),
		Connection(6),
		Authentication(7),
		AuthenticationCancelled(8);

		private final int label;

		private ErrorCategory(int label) {
			this.label = label;
		}

		public int getInteger() {
			return label;
		}
	}

	public static class Error { // Error structure returned by getLastError
		public ErrorCategory category;
		public String message;

		public Error(ErrorCategory cat, String msg) {
			category = cat;
			message = msg;
		}

		@Override
		public String toString() {
			return message;
		}
	}

	public static class DatabaseNonFatalException extends Exception {
		private static final long serialVersionUID = 1L;

		public DatabaseNonFatalException(String message) {
			super(message);
		}
	}

	/**
	 * Determine if the connected database supports a user password change.
	 * @return true if a password change is permitted, else false.
	 */
	public default boolean isPasswordChangeAllowed() {
		return getStatus() == Status.Ready &&
			getConnectionType() == ConnectionType.SSL_Password_Authentication;
	}

	/**
	 * Issue password change request to the server.
	 * The method {@link #isPasswordChangeAllowed()} must be invoked first to ensure that
	 * the user password may be changed.
	 * @param username to change
	 * @param newPassword is password data
	 * @return null if change was successful, or the error message
	 */
	public default String changePassword(String username, char[] newPassword) {
		if (getStatus() != Status.Ready) {
			return "Connection not established";
		}
		if (!isPasswordChangeAllowed()) {
			return "Password change not supported";
		}
		PasswordChange passwordChange = new PasswordChange();
		try {
			passwordChange.username = username;
			passwordChange.newPassword = newPassword;
			ResponsePassword response = passwordChange.execute(this);
			if (!response.changeSuccessful) {
				return response.errorMessage;
			}
		}
		finally {
			passwordChange.clearPassword();
		}
		return null;
	}

	/**
	 * @return the status of the current connection with this database
	 */
	public Status getStatus();

	/**
	 * @return the type of connection
	 */
	public ConnectionType getConnectionType();

	/**
	 * @return username (being used to establish connection)
	 */
	public String getUserName();

	/**
	 * Set a specific user name for connection.  Must be called before connection is initialized.
	 * If this method is not called, connection will use user name of process
	 * 
	 * @param userName the user name
	 */
	public void setUserName(String userName);

	/**
	 * @return factory the database is using to create LSHVector objects
	 */
	public LSHVectorFactory getLSHVectorFactory();

	/**
	 * @return an information object giving general characteristics and descriptions of this database
	 */
	public DatabaseInformation getInfo();

	/**
	 * Return -1 if info layout version is earlier than current client expectation
	 * Return 1 if info layout version is later than current client expectation
	 * Return 0 if info version and client version are the same
	 * @return comparison of actual database layout with layout expected by client
	 */
	public int compareLayout();

	/**
	 * Return the {@link BSimServerInfo server info object} for this database
	 * @return the server info object
	 */
	public BSimServerInfo getServerInfo();

	/**
	 * Get the 
	 * @return
	 */
	@Deprecated
	public String getURLString();

	/**
	 * Initialize (a connection with) the database. If initialization is not successful, this routine will
	 * return false and an error description can be obtained using getLastError
	 * @return true if the database ready for querying
	 */
	public boolean initialize();

	/**
	 * Close down (the connection with) the database
	 */
	@Override
	public void close();

	/**
	 * If the last query failed to produce a response, use this method to recover the error message
	 * @return a String describing the error
	 */
	public Error getLastError();

	/**
	 * Send a query to the database.  The response is returned as a QueryResponseRecord.
	 * If this is null, an error has occurred and an error message can be obtained from getLastError
	 * @param query an object describing the query
	 * @return the response object or null if there is an error
	 */
	public QueryResponseRecord query(BSimQuery<?> query);

	public static void checkSettingsForQuery(DescriptionManager manage, DatabaseInformation info)
			throws LSHException {
		final int res = info.checkSignatureSettings(manage.getMajorVersion(),
			manage.getMinorVersion(), manage.getSettings());
		if (res <= 1) {
			return;
		}
		if (res == 4) {
			return;
		}
		if (res == 3) {
			throw new LSHException("Query signature data has no setting information");
		}
		throw new LSHException("Query signature data does not match database");
	}

	public static boolean checkSettingsForInsert(DescriptionManager manage,
			DatabaseInformation info) throws LSHException, DatabaseNonFatalException {
		if (manage.numFunctions() == 0) {
			throw new DatabaseNonFatalException("Empty signature file");
		}
		int res = info.checkSignatureSettings(manage.getMajorVersion(), manage.getMinorVersion(),
			manage.getSettings());
		if (res == 0) {
			return false;
		}
		if (res == 1) {
			throw new LSHException(
				"Trying to insert signature data with slight differences in settings");
		}
		if (res == 4) {
			return true; // This apparently is the first insert
		}
		if (res == 3) {
			throw new LSHException("Trying to insert signature data with no setting information");
		}
		throw new LSHException(
			"Trying to insert signature data with settings that don't match database");
	}

	public static String constructFatalError(int flags, ExecutableRecord newrec,
			ExecutableRecord orig) {
		String res = null;
		if ((flags & ExecutableRecord.METADATA_ARCH) != 0) {
			res = newrec.getNameExec() + " already ingested with different architecture field: " +
				orig.getArchitecture();
		}
		else if ((flags & ExecutableRecord.METADATA_COMP) != 0) {
			res = newrec.getNameExec() + " already ingested with different compiler field: " +
				orig.getNameCompiler();
		}
		else if ((flags & ExecutableRecord.METADATA_LIBR) != 0) {
			res = newrec.getNameExec() + " already ingested -- library field differs!!";
		}
		else if ((flags & ExecutableRecord.METADATA_REPO) != 0) {
			res = newrec.getNameExec() + " already ingested from a different repository: " +
				orig.getRepository();
		}
		return res;
	}

	public static String constructNonfatalError(int flags, ExecutableRecord newrec,
			ExecutableRecord orig) {
		String res;
		if ((flags & ExecutableRecord.METADATA_NAME) != 0) {
			res = newrec.getNameExec() + " already ingested with a different name: " +
				orig.getNameExec();
		}
		else if ((flags & ExecutableRecord.METADATA_PATH) != 0) {
			res = newrec.getNameExec() + " already ingested under a different path: " +
				orig.getPath();
		}
		else if ((flags & ExecutableRecord.METADATA_DATE) != 0) {
			res = newrec.getNameExec() + " already ingested with a different date: " +
				orig.getDate().toString();
		}
		else {
			res = newrec.getNameExec() + " already ingested with UNKNOWN difference in metadata";
		}
		return res;
	}

	public static Configuration loadConfigurationTemplate(String configname) throws LSHException {
		ResourceFile moduleDataSubDirectory;
		final Configuration config = new Configuration();
		try {
			moduleDataSubDirectory = Application.getModuleDataSubDirectory("");
			config.loadTemplate(moduleDataSubDirectory, configname);
		}
		catch (final FileNotFoundException e) {
			throw new LSHException("Missing configuration data: " + e.getMessage());
		}
		catch (final IOException e) {
			throw new LSHException("Could open module data directory");
		}
		catch (final SAXException e) {
			throw new LSHException("Unable to parse configuration template");
		}
		return config;
	}

	/**
	 * Central location for building vector factory used by FunctionDatabase
	 * @return the LSHVectorFactory object
	 */
	public static WeightedLSHCosineVectorFactory generateLSHVectorFactory() {
		return new WeightedLSHCosineVectorFactory();
	}

	/**
	 * Returns a list of all configuration template files. 
	 * 
	 * @return list of template files
	 */
	public static List<File> getConfigurationTemplates() {
		List<File> templateFiles = new ArrayList<>();

		ResourceFile moduleDataSubDirectory;
		try {
			moduleDataSubDirectory = Application.getModuleDataSubDirectory("");
			File templateDir = new File(moduleDataSubDirectory.getAbsolutePath());
			if (!templateDir.exists()) {
				return Collections.emptyList();
			}

			FilenameFilter nameFilter = (dir, name) -> {
				if (!name.endsWith(".xml")) {
					return false;
				}

				return true;
			};

			File[] files = templateDir.listFiles(nameFilter);
			if (files != null) {
				for (File file : files) {
					if (isConfigTemplate(file)) {
						templateFiles.add(file);
					}
				}
			}
		}
		catch (IOException e) {
			Msg.error(null, "Error retrieving configuration templates", e);
		}

		return templateFiles;
	}

	/**
	 * Determines if a given xml file is a config template. This is done by opening the file
	 * and checking for the presence of a <dbconfig> root tag.
	 * 
	 * @param file the file to inspect
	 * @return true if the file is config template
	 */
	static boolean isConfigTemplate(File file) {

		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.parse(file);

			Element rootElem = doc.getDocumentElement();
			if (rootElem.getTagName().equals("dbconfig")) {
				return true;
			}
		}
		catch (ParserConfigurationException | SAXException | IOException e) {
			Msg.error(null, "Error inspecting xml file", e);
		}

		return false;
	}

	/**
	 * Get the maximum number of functions to be queried per staged query when searching
	 * for similar functions.
	 * @return maximum number of functions to be queried per staged query, or 0 for default
	 * which is generally ten (10) per stage.  See {@link SFQueryInfo#DEFAULT_QUERIES_PER_STAGE}.
	 */
	public default int getQueriedFunctionsPerStage() {
		return 0;
	}

	/**
	 * Get the maximum number of functions to be queried per staged query when performing
	 * an overview query.
	 * @return maximum number of functions to be queried per staged query, or 0 for default
	 * which is generally ten (10) per stage.  See {@link SFOverviewInfo#DEFAULT_QUERIES_PER_STAGE}.
	 */
	public default int getOverviewFunctionsPerStage() {
		return 0;
	}

}
