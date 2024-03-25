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
package ghidra.features.bsim.query.ingest;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import javax.help.UnsupportedOperationException;

import org.apache.commons.lang3.StringUtils;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.decompiler.DecompileException;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.FunctionDatabase.Error;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.FunctionDatabase.Status;
import ghidra.features.bsim.query.client.Configuration;
import ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.features.bsim.query.protocol.ResponseDelete.DeleteResult;
import ghidra.framework.Application;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

public class BulkSignatures implements AutoCloseable {

	// FIXME: May need to use Msg.showError for popup messages in GUI workbench case

	private final BSimServerInfo bsimServerInfo; // may be null
	private final String connectingUserName;

	private FunctionDatabase querydb;

	/**
	 * Constructor
	 * @param bsimServerInfo the BSim database server info.  May be {@code null} if use limited to
	 * signature and update generation only (based upon configuration template).
	 * @param connectingUserName user name to use for BSim server authentication.  May be null if
	 * not required or default should be used (see {@link ClientUtil#getUserName()}).
	 * @throws MalformedURLException if the given URL string cannot be parsed
	 */
	public BulkSignatures(BSimServerInfo bsimServerInfo, String connectingUserName)
			throws MalformedURLException {
		this.bsimServerInfo = bsimServerInfo;
		this.connectingUserName =
			connectingUserName != null ? connectingUserName : ClientUtil.getUserName();
	}

	private void checkBSimServerOperation() {
		if (bsimServerInfo == null) {
			throw new UnsupportedOperationException("BSim server has not been specified");
		}
	}

	/**
	 *
	 * 
	 * @param async true if database commits should be synchronous
	 * @return  the {@link DatabaseInformation} object returned from a successful connect
	 * @throws IOException if there's a problem creating the connection
	 */
	private DatabaseInformation establishQueryServerConnection(boolean async) throws IOException {

		if (querydb != null) {
			return querydb.getInfo();
		}

		checkBSimServerOperation();

		querydb = BSimClientFactory.buildClient(bsimServerInfo, async);
		if (querydb.getStatus() == Status.Unconnected) { // may have previously connected
			querydb.setUserName(connectingUserName);
		}

		if (!querydb.initialize()) {
			throw new IOException(querydb.getLastError().message);
		}

		DatabaseInformation info = querydb.getInfo();
		if (info == null) {
			Error lastError = querydb.getLastError();
			if (lastError != null && lastError.category == ErrorCategory.Nodatabase) {
				throw new IOException(lastError.message);
			}
			throw new IOException("Unknown error connection to: " + bsimServerInfo.toString());
		}

		Msg.debug(this, "Connected to " + info.databasename);
		return info;
	}

	/**
	 * This will be automatically invoked when BulkSignatures is out of scope, if using
	 * try-with-resources to create it. When this happens we need to clean up the 
	 * connection.
	 */
	@Override
	public void close() {
		closeConnection();
	}

	/**
	 * Closes the current database connection.
	 */
	private void closeConnection() {
		if (querydb != null) {
			querydb.close();
			querydb = null;
		}
	}

	private List<File> gatherXml(String prefix, File dir) throws IOException {
		List<File> res = new ArrayList<File>();
		File[] listFiles = dir.listFiles();
		if (listFiles == null) {
			throw new IOException("Bad xml directory");
		}
		for (File file : listFiles) {
			if (file.getName().startsWith(prefix)) {
				res.add(file);
			}
		}
		return res;
	}

	private void loadSignatureXml(File file, DescriptionManager manage)
			throws SAXException, IOException, LSHException {
		ErrorHandler handler = SpecXmlUtils.getXmlHandler();
		XmlPullParser parser = new NonThreadedXmlPullParserImpl(file, handler, false);
		manage.restoreXml(parser, querydb.getLSHVectorFactory());
	}

	protected void sendXmlToQueryServer(File dir, URL ghidraOverrideURL, String filter,
			TaskMonitor monitor)
			throws IOException, SAXException, LSHException, CancelledException {
		establishQueryServerConnection(true);
		if (filter == null) {
			filter = "sigs_";
		}
		else {
			filter = "sigs_" + filter;
		}
		List<File> files = gatherXml(filter, dir);

		if (files.isEmpty()) {
			throw new IOException("No signature files found in " + dir.getAbsolutePath());
		}

		monitor.setMessage("Writing signatures");
		monitor.setMaximum(files.size());

		for (File file : files) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			Msg.info(this, "Writing signatures for " + file.getName());
			InsertRequest insertreq = new InsertRequest();
			if (ghidraOverrideURL != null) {
				insertreq.repo_override =
					GhidraURL.getProjectURL(ghidraOverrideURL).toExternalForm();
				insertreq.path_override = GhidraURL.getProjectPathname(ghidraOverrideURL);
			}
			loadSignatureXml(file, insertreq.manage);
			if (insertreq.manage.numFunctions() == 0) {
				Msg.warn(this, file.getName() + ": does not define any functions");
				continue;
			}
			if (insertreq.execute(querydb) == null) {
				Error lastError = querydb.getLastError();
				if ((lastError.category == ErrorCategory.Format) ||
					(lastError.category == ErrorCategory.Nonfatal)) {
					Msg.warn(this, file.getName() + ": " + lastError.message);
				}
				else {
					throw new IOException(file.getName() + ": " + lastError.message);
				}
			}
		}
	}

	protected void sendUpdateToServer(File dir) throws IOException, SAXException, LSHException {
		establishQueryServerConnection(true);
		List<File> files = gatherXml("update_", dir);

		if (files.isEmpty()) {
			throw new IOException("No update files found in " + dir.getAbsolutePath());
		}

		for (File file : files) {
			Msg.info(this, "Updating metadata for " + file.getName());
			QueryUpdate update = new QueryUpdate();
			loadSignatureXml(file, update.manage);
			ResponseUpdate respup = update.execute(querydb);
			if (respup == null) {
				Error lastError = querydb.getLastError();
				if ((lastError.category == ErrorCategory.Format) ||
					(lastError.category == ErrorCategory.Nonfatal)) {
					Msg.warn(this, file.getName() + ": " + lastError.message);
				}
				else {
					throw new IOException(file.getName() + ": " + lastError.message);
				}
			}
			else {
				if (!respup.badexe.isEmpty()) {
					for (ExecutableRecord erec : respup.badexe) {
						Msg.error(this, "Unable to find executable: " + erec.getNameExec());
					}
				}
				if (!respup.badfunc.isEmpty()) {
					int max = respup.badfunc.size();
					if (max > 3) {
						Msg.error(this, "Could not find " +
							Integer.toString(respup.badfunc.size()) + " functions");
						max = 3;
					}
					for (int j = 0; j < max; ++j) {
						FunctionDescription func = respup.badfunc.get(j);
						Msg.error(this, "Could not update function " + func.getFunctionName());
					}
				}
				if (respup.exeupdate > 0) {
					Msg.info(this,
						"Updated " + Integer.toString(respup.exeupdate) + " executables");
				}
				if (respup.funcupdate > 0) {
					Msg.info(this, "Updated " + Integer.toString(respup.funcupdate) + " functions");
				}
				if (respup.exeupdate == 0 && respup.funcupdate == 0) {
					Msg.info(this, "No changes");
				}
			}
		}
	}

	private DatabaseInformation createQueryDatabase(String template, String name, String owner,
			String description, boolean track) throws IOException {
		CreateDatabase command = new CreateDatabase();
		command.info = new DatabaseInformation();
		// Put in fields provided on the command line
		// If they are null, the template will fill them in
		command.info.databasename = name;
		command.info.owner = owner;
		command.info.description = description;
		command.config_template = template;
		command.info.trackcallgraph = track;
		ResponseInfo response = command.execute(querydb);
		if (response == null) {
			throw new IOException(querydb.getLastError().message);
		}
		return response.info;
	}

	private void formatCategories(List<String> execats, StringBuilder buf) {
		if (execats == null) {
			return;
		}
		buf.append(" Categories:\n");
		for (String execat : execats) {
			buf.append("   ");
			buf.append(execat);
			buf.append("\n");
		}
	}

	private void formatFunctionTags(List<String> tags, StringBuilder buf) {
		if (tags == null) {
			return;
		}
		buf.append(" Function Tags:\n");
		for (String tag : tags) {
			buf.append("   ");
			buf.append(tag);
			buf.append("\n");
		}
	}

	private String formatDatabaseDetails(DatabaseInformation info) {
		StringBuilder buf = new StringBuilder();
		buf.append("Using configuration for:\n");
		buf.append(" Database: ");
		buf.append(info.databasename);
		buf.append("\n");
		buf.append(" Owner:    ");
		buf.append(info.owner);
		buf.append("\n");
		formatCategories(info.execats, buf);
		formatFunctionTags(info.functionTags, buf);
		if (info.dateColumnName != null) {
			buf.append(" Date column: ");
			buf.append(info.dateColumnName);
			buf.append("\n");
		}
		return buf.toString();
	}

	protected File generateSignaturesFromServer(URL ghidraURL, String xmlDirectory,
			boolean overwrite, String configtemplate, TaskMonitor monitor)
			throws Exception, CancelledException {

		File dir = establishTemporaryDirectory(xmlDirectory);

		DatabaseInformation info;
		LSHVectorFactory vectorFactory = null;
		if (configtemplate == null) {
			info = establishQueryServerConnection(false);
			Msg.debug(this, "Attempting to pull configuration from: " + bsimServerInfo.toString());
			vectorFactory = querydb.getLSHVectorFactory();
		}
		else {
			// User gave an overriding configuration name on the command line
			Configuration config = FunctionDatabase.loadConfigurationTemplate(configtemplate);
			info = config.info;
			vectorFactory = FunctionDatabase.generateLSHVectorFactory();
			vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);
		}

		// TODO: Should this output differ for command-line vs workbench? debug only?
		Msg.info(this, formatDatabaseDetails(info));

		String repositoryURLString = GhidraURL.getProjectURL(ghidraURL).toExternalForm();
		SignatureRepository sigrepo =
			new SignatureRepository(dir, repositoryURLString, overwrite, info, vectorFactory);

		sigrepo.process(ghidraURL, monitor);

		return dir;
	}

	protected File generateUpdatesFromServer(URL ghidraURL, String xmlDirectory, boolean overwrite,
			String configtemplate, TaskMonitor monitor) throws Exception, CancelledException {

		File dir = establishTemporaryDirectory(xmlDirectory);

		DatabaseInformation info;
		LSHVectorFactory vectorFactory = null;
		if (configtemplate == null) {
			info = establishQueryServerConnection(false);
			vectorFactory = querydb.getLSHVectorFactory();
		}
		else {
			// User gave an overriding configuration name on the command line
			Configuration config = FunctionDatabase.loadConfigurationTemplate(configtemplate);
			info = config.info;
			vectorFactory = FunctionDatabase.generateLSHVectorFactory();
			vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);
		}

		// TODO: Should this output differ for command-line vs workbench? debug only?
		Msg.info(this, formatDatabaseDetails(info));

		String repositoryURLString = GhidraURL.getProjectURL(ghidraURL).toExternalForm();
		UpdateRepository updaterepo =
			new UpdateRepository(dir, repositoryURLString, overwrite, info, vectorFactory);

		updaterepo.process(ghidraURL, monitor);

		return dir;
	}

	/**
	 * Creates a new BSim database with a given set of properties.
	 * 
	 * @param configTemplate the type of database to create
	 * @param name the name of the database
	 * @param owner the owner of the database
	 * @param description the database description
	 * @param trackCall if true, the database should track callgraph information
	 * @throws IOException if there's an error building the {@link BSimClientFactory}
	 */
	public void createDatabase(String configTemplate, String name, String owner, String description,
			boolean trackCall) throws IOException {

		closeConnection();

		checkBSimServerOperation();

		querydb = BSimClientFactory.buildClient(bsimServerInfo, true);
		if (querydb.getStatus() == Status.Unconnected) { // may have previously connected
			querydb.setUserName(connectingUserName);
		}

		// TODO: Should this output differ for command-line vs workbench? debug only?
		try {
			DatabaseInformation info =
				createQueryDatabase(configTemplate, name, owner, description, trackCall);

			StringBuilder buf = new StringBuilder();
			buf.append("Created database: ");
			buf.append(info.databasename);
			buf.append("\n");
			buf.append("   owner       = ");
			buf.append(info.owner);
			buf.append("\n");
			buf.append("   description = ");
			buf.append(info.description);
			buf.append("\n");
			buf.append("   template    = ");
			buf.append(configTemplate);
			buf.append("\n");

			// TODO: Should this output differ for command-line vs workbench? debug only?
			Msg.info(this, buf.toString());
		}
		catch (IOException ex) {
			Msg.error(this, "Unable to create database: " + ex.getMessage());
			return;
		}

		// Always attempt to initialize after creation.
		boolean success = querydb.initialize();
		if (!success) {
			Msg.error(this, "Database initialization error: " + querydb.getLastError().message);
		}
	}

	/**
	 * Adds function signatures from the specified project to the BSim database
	 * @param ghidraURL ghidra repository from which to pull files for signature generation
	 * @param sigsLocation the location where signature files will be stored
	 * @param overwrite if true, overwrites any existing signatures
	 * @param monitor the task monitor
	 * @throws Exception if there's an error during the operation
	 * @throws CancelledException if processing is cancelled
	 */
	public void signatureRepo(URL ghidraURL, String sigsLocation, boolean overwrite,
			TaskMonitor monitor) throws Exception, CancelledException {

		String xmlDirectory = null;
		boolean usestmpdir = false;

		if (!StringUtils.isBlank(sigsLocation)) {
			xmlDirectory = sigsLocation;
		}
		else {
			usestmpdir = true;
		}

		File dir = generateSignaturesFromServer(ghidraURL, xmlDirectory, overwrite, null, monitor);
		sendXmlToQueryServer(dir, null, null, monitor);
		if (usestmpdir) {
			deleteTemporaryDirectory(dir);
		}
	}

	/**
	 * Updates function signatures from the specified project to the BSim database
	 * @param ghidraURL ghidra repository from which to pull files for signature generation
	 * @param sigsLocation the location where update XML files are
	 * @param overwrite if true, overwrites any existing signatures
	 * @param monitor the task monitor
	 * @throws Exception if there's an error during the operation
	 * @throws CancelledException if processing is cancelled
	 */
	public void updateRepoSignatures(URL ghidraURL, String sigsLocation, boolean overwrite,
			TaskMonitor monitor) throws Exception, CancelledException {

		String xmlDirectory = null;
		boolean usestmpdir = false;

		if (!StringUtils.isAnyBlank(sigsLocation)) {
			xmlDirectory = sigsLocation;
		}
		else {
			usestmpdir = true;
		}

		File dir = generateUpdatesFromServer(ghidraURL, xmlDirectory, overwrite, null, monitor);
		sendUpdateToServer(dir);
		if (usestmpdir) {
			deleteTemporaryDirectory(dir);
		}
	}

	/**
	 * Deletes a specified executable from the database.
	 * 
	 * @param md5 the MD5 of the executable to delete
	 * @param name the name of the executable to delete
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	public void deleteExecutable(String md5, String name) throws IOException, LSHException {

		if (StringUtils.isAnyBlank(md5) && StringUtils.isAnyBlank(name)) {
			throw new IOException("Must specify \"md5=\" or \"name=\" option");
		}

		ExeSpecifier spec = new ExeSpecifier();
		spec.exemd5 = md5;
		spec.exename = name;
		spec.arch = null;
		spec.execompname = null;

		deleteExecutables(spec);
	}

	/**
	 * Deletes a specified executable from the database.
	 * 
	 * @param spec the spec that indicates what executable to delete
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	protected void deleteExecutables(ExeSpecifier spec) throws IOException, LSHException {

		QueryDelete query = new QueryDelete();
		query.addSpecifier(spec);
		establishQueryServerConnection(true);
		ResponseDelete respdel = query.execute(querydb);
		if (respdel == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException("Could not perform delete: " + lastError.message);
		}

		// TODO: Should this output differ for command-line vs workbench? debug only?
		for (DeleteResult delres : respdel.reslist) {
			Msg.info(this, "Successfully deleted " + delres.name + "(" +
				Integer.toString(delres.funccount) + " functions)" + delres.md5);
		}
		for (ExeSpecifier missedSpec : respdel.missedlist) {
			Msg.error(this, "Unable to uniquely identify: " + missedSpec.getExeNameWithMD5());
		}
	}

	/**
	 * Drops the current BSim database index which can allow for faster signature ingest after
	 * which a {@link #rebuildIndex()} may be performed.  Dropping the index may also be done to
	 * obtain more accurate results albeit at the cost of performance.
	 * 
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	public void dropIndex() throws IOException, LSHException {
		DatabaseInformation info = establishQueryServerConnection(false);
		AdjustVectorIndex query = new AdjustVectorIndex();
		query.doRebuild = false;
		ResponseAdjustIndex response = query.execute(querydb);
		if (response == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException("Could not drop index: " + lastError.message);
		}
		String dbDetail = "for database " + info.databasename + " (" + bsimServerInfo + ")";
		if (!response.success) {
			String msg = "Could not drop the index " + dbDetail;
			if (!response.operationSupported) {
				msg += ": operation not supported";
			}
			Msg.error(this, msg);
		}
		else {
			Msg.info(this, "Successfully dropped index " + dbDetail);
		}
	}

	/**
	 * Rebuilds the current BSim database index.
	 * 
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	public void rebuildIndex() throws IOException, LSHException {
		DatabaseInformation info = establishQueryServerConnection(false);
		AdjustVectorIndex query = new AdjustVectorIndex();
		query.doRebuild = true;
		System.out.println("Starting rebuild ...");
		ResponseAdjustIndex response = query.execute(querydb);
		if (response == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException("Could not rebuild index: " + lastError.message);
		}
		String dbDetail = "for database " + info.databasename + " (" + bsimServerInfo + ")";
		if (!response.success) {
			String msg = "Could not rebuild index " + dbDetail;
			if (!response.operationSupported) {
				msg += ": operation not supported";
			}
			Msg.error(this, msg);
		}
		else {
			Msg.info(this, "Successfully rebuilt index " + dbDetail);
		}
	}

	/**
	 * Performs a prewarm command on the BSim database.
	 * 
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	public void prewarm() throws IOException, LSHException {
		DatabaseInformation info = establishQueryServerConnection(false);
		PrewarmRequest request = new PrewarmRequest();
		ResponsePrewarm response = request.execute(querydb);
		if (response == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException("Prewarm failed: " + lastError.message);
		}
		String dbDetail = "for database " + info.databasename + " (" + bsimServerInfo + ")";
		if (!response.operationSupported) {
			Msg.error(this, "Prewarm operation not supported " + dbDetail);
		}
		else {
			Msg.info(this, "Successfully prewarmed " + Integer.toString(response.blockCount) +
				" blocks of main index " + dbDetail);
		}
	}

	/**
	 * Returns a list of all executable records meeting a set of search criteria.
	 * 
	 * @param limit the maximum number of results to return
	 * @param md5Filter MD5 filter
	 * @param exeNameFilter executable name filter
	 * @param archFilter architecture filter
	 * @param compilerFilter compiler name filter
	 * @param sortCol the main sort column (either name or md5)
	 * @param incFakes if true, include executables with an MD5 that we generate
	 * @return the list of executables matching the filters
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	protected List<ExecutableRecord> getExes(int limit, String md5Filter, String exeNameFilter,
			String archFilter, String compilerFilter, String sortCol, boolean incFakes)
			throws IOException, LSHException {

		establishQueryServerConnection(false);
		ExeTableOrderColumn sortEnum;
		if (sortCol != null) {
			sortEnum = ExeTableOrderColumn.valueOf(sortCol.toUpperCase());
		}
		else {
			sortEnum = ExeTableOrderColumn.MD5;
		}

		QueryExeInfo exeQuery = new QueryExeInfo(limit, md5Filter, exeNameFilter, archFilter,
			compilerFilter, sortEnum, incFakes);

		ResponseExe response = exeQuery.execute(querydb);
		if (response == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException("Could not perform getexeinfo: " + lastError.message);
		}

		return response.records;
	}

	/**
	 * Retrieves the number of records in the database that match the filter criteria.
	 * 
	 * @param md5Filter the MD5 value must contain this
	 * @param exeNameFilter the executable name must contain this
	 * @param archFilter the architecture type must match this
	 * @param compilerFilter the compiler type must match this
	 * @param incFakes if true, include executables with an MD5 that we created
	 * @return the number of executables matching the filter criteria
	 * @throws IOException if there's a problem establishing the database connection
	 */
	public int getCount(String md5Filter, String exeNameFilter, String archFilter,
			String compilerFilter, boolean incFakes) throws IOException {

		establishQueryServerConnection(false);

		QueryExeCount exeQuery =
			new QueryExeCount(md5Filter, exeNameFilter, archFilter, compilerFilter, incFakes);
		ResponseExe response = exeQuery.execute(querydb);
		if (response == null) {
			return 0;
		}

		return response.recordCount;
	}

	/**
	 * Remove one layer of quoting
	 * @param val is the string which might be quoted
	 * @return the string with any outer quote characters stripped
	 */
	protected static String dequoteString(String val) {
		if (val.length() < 3) {
			return val;
		}
		if (val.charAt(0) != '\"') {
			return val;
		}
		if (val.charAt(val.length() - 1) != '\"') {
			return val;
		}
		val = val.substring(1, val.length() - 1);
		return val;
	}

	/**
	 * Performs the work of updating the metadata. This will build the query
	 * object, establish the database connection, and perform the query.
	 * 
	 * @param name the database name
	 * @param owner the database owner
	 * @param description the database description
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	protected void installMetadata(String name, String owner, String description)
			throws IOException, LSHException {

		DatabaseInformation info = establishQueryServerConnection(false);

		InstallMetadataRequest req = new InstallMetadataRequest();
		req.dbname = name;
		req.owner = owner;
		req.description = description;
		ResponseInfo resp = req.execute(querydb);
		if (resp == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException("Could not change metadata: " + lastError.message);
		}
		info = resp.info;
		Msg.info(this, "Updated BSim metadata: ");
		Msg.info(this, "   Database:     " + info.databasename);
		Msg.info(this, "   Owner:        " + info.owner);
		Msg.info(this, "   Description:  " + info.description);
	}

	/**
	 * Performs the work of installing a new category name. This will build the query
	 * object, establish the database connection, and perform the query.
	 * 
	 * @param categoryName the category name to insert
	 * @param isDate true if this is a date category
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	public void installCategory(String categoryName, boolean isDate)
			throws LSHException, IOException {
		DatabaseInformation info = establishQueryServerConnection(false);

		InstallCategoryRequest req = new InstallCategoryRequest();
		req.type_name = dequoteString(categoryName);
		req.isdatecolumn = isDate;

		ResponseInfo resp = req.execute(querydb);
		if (resp == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException("Could not install new category: " + lastError.message);
		}
		info = resp.info;

		StringBuilder buf = new StringBuilder();
		buf.append("BSim Database ");
		buf.append(info.databasename);
		buf.append(" now contains:\n");
		formatCategories(info.execats, buf);
		if (info.dateColumnName != null) {
			buf.append(" Date column: ");
			buf.append(info.dateColumnName);
			buf.append("\n");
		}

		// TODO: Should this output differ for command-line vs workbench? debug only?
		Msg.info(this, buf.toString());
	}

	/**
	 * Performs the work of inserting a new function tag name into the database. This 
	 * will build the query object, establish the database connection, and perform the query.
	 * 
	 * @param tagName the tag name to insert
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	public void installTags(String tagName) throws IOException, LSHException {
		DatabaseInformation info = establishQueryServerConnection(false);
		InstallTagRequest req = new InstallTagRequest();
		req.tag_name = dequoteString(tagName);
		ResponseInfo resp = req.execute(querydb);
		if (resp == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException(lastError.message);
		}
		info = resp.info;

		StringBuilder buf = new StringBuilder();
		buf.append("BSim Database ");
		buf.append(info.databasename);
		buf.append(" now contains:\n");
		formatFunctionTags(info.functionTags, buf);

		// TODO: Should this output differ for command-line vs workbench? debug only?
		Msg.info(this, buf.toString());
	}

	protected static int readQueryPairs(XmlPullParser parser, int count, List<PairInput> pairs) {
		for (int i = 0; i < count; ++i) {
			if (!parser.peek().isStart()) {
				return i;
			}
			PairInput pairInput = new PairInput();
			pairInput.restoreXml(parser);
			pairs.add(pairInput);
		}
		return count;
	}

	/**
	 * Compares pairs of functions specified in an input (XML) file, and writes
	 * the results to an output file.
	 * 
	 * @param inputFile input XML file
	 * @param outputFile output XML file
	 * @throws IOException if there is a problem establishing the server connection
	 * @throws SAXException if an XML parse error occurs
	 * @throws LSHException if there is a problem querying the database
	 */
	protected void queryPair(File inputFile, File outputFile)
			throws IOException, SAXException, LSHException {
		if (!inputFile.isFile()) {
			throw new IOException(inputFile.getAbsolutePath() + " is not an XML file");
		}
		if (outputFile.isFile()) {
			Msg.info(this, "Overwriting file " + outputFile.getAbsolutePath());
			outputFile.delete();
		}
		establishQueryServerConnection(true);
		QueryPair query = new QueryPair();
		query.pairs = new ArrayList<PairInput>();
		ErrorHandler handler = SpecXmlUtils.getXmlHandler();
		XmlPullParser parser = XmlPullParserFactory.create(inputFile, handler, false);
		parser.start("querypair");

		try (FileWriter writer = new FileWriter(outputFile)) {
			writer.append("<responsepair>\n");
			ResponsePair.Accumulator accumulator = new ResponsePair.Accumulator();
			ResponsePair finalResponse = new ResponsePair();
			int count = readQueryPairs(parser, 20, query.pairs);
			while (count != 0) {
				ResponsePair responsePair = query.execute(querydb);
				if (responsePair == null) {
					Error lastError = querydb.getLastError();
					throw new LSHException(lastError.message);
				}
				for (PairNote note : responsePair.notes) {
					note.saveXml(writer);
				}
				finalResponse.scale = responsePair.scale;
				accumulator.merge(responsePair);
				query.pairs.clear();
				query.clearResponse();
				count = readQueryPairs(parser, 20, query.pairs);
			}
			parser.end();
			finalResponse.fillOutStatistics(accumulator);
			finalResponse.saveXmlTail(writer);
			writer.append("</responsepair>\n");
		}
	}

	/**
	 * Execute the specified {@link QueryName} query and print the formatted results to the 
	 * specified {@code outStream}.
	 * 
	 * @param query function name query
	 * @param outStream stream to receive formatted output
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	protected void printFunctions(QueryName query, PrintStream outStream)
			throws IOException, LSHException {

		establishQueryServerConnection(true);
		ResponseName resp = query.execute(querydb);
		if (resp == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException(lastError.message);
		}
		resp.printRaw(outStream, querydb.getLSHVectorFactory(), 0);
	}

	/**
	 * Exports information about a binary to a local folder in XML format.
	 * 
	 * @param resultFolder the folder where the results will be stored
	 * @param md5 the MD5 of the executables to export
	 * @param name the name of the executables to export
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	public void dumpSigs(File resultFolder, String md5, String name)
			throws IOException, LSHException {

		if (StringUtils.isAnyBlank(md5) && StringUtils.isAnyBlank(name)) {
			throw new IOException("Must specify \"md5=\" or \"name=\"");
		}

		QueryName query = new QueryName();
		query.spec.exemd5 = md5;
		query.spec.exename = name;
		query.spec.arch = null;
		query.spec.execompname = null;

		doDumpSigs(resultFolder, query);
	}

	/**
	 * Exports information about a binary to a local folder in XML format.
	 * 
	 * @param resultFolder the folder where the results will be stored
	 * @param query the query object containing the params of the query
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	protected void doDumpSigs(File resultFolder, QueryName query) throws IOException, LSHException {
		if (!resultFolder.isDirectory()) {
			throw new IOException(resultFolder.getAbsolutePath() + " is not a valid directory");
		}

		DatabaseInformation info = establishQueryServerConnection(true);
		query.fillinCallgraph = info.trackcallgraph;
		ResponseName responseName = query.execute(querydb);
		if (responseName == null) {
			Error lastError = querydb.getLastError();
			throw new LSHException(lastError.message);
		}
		if (!responseName.uniqueexecutable) {
			throw new LSHException("Could not determine unique executable");
		}
		ExecutableRecord exe;
		if (!StringUtils.isAllBlank(query.spec.exemd5)) {
			exe = responseName.manage.findExecutable(query.spec.exemd5);
		}
		else {
			exe = responseName.manage.findExecutable(query.spec.exename, query.spec.arch,
				query.spec.execompname);
		}
		String basename = "sigs_" + exe.getMd5();
		File sigFile = new File(resultFolder, basename);

		try (FileWriter writer = new FileWriter(sigFile)) {
			responseName.manage.saveXml(writer);
		}
	}

	protected File establishTemporaryDirectory(String xmldir) throws IOException {
		File dir;
		if (xmldir == null) {
			File tmpDir = Application.getUserTempDirectory();
			if (tmpDir == null) {
				throw new IOException("Could not find temporary directory");
			}
			dir = new File(tmpDir, "bulkinsert_xml");
			deleteTemporaryDirectory(dir);
		}
		else {
			dir = new File(xmldir);
		}
		if (dir.exists() == false) {
			if (dir.mkdir() == false) {
				throw new IOException("Unable to create temp directory: " + dir.getAbsolutePath());
			}
		}
		else if (dir.isDirectory() == false) {
			throw new IOException(dir.getAbsolutePath() + ": is not a directory");
		}
		dir = dir.getCanonicalFile();
		return dir;
	}

	private void deleteTemporaryDirectory(File tempDir) throws IOException {
		if (!tempDir.exists()) {
			return;
		}
		File[] listFiles = tempDir.listFiles();
		if (listFiles == null) {
			throw new IOException(
				"Could not list files in temp directory: " + tempDir.getAbsolutePath());
		}
		for (File listFile : listFiles) {
			if (!listFile.delete()) {
				throw new IOException(
					"Unable to delete temporary file: " + listFile.getAbsolutePath());
			}
		}
		if (!tempDir.delete()) {
			throw new IOException("Unable to delete temp directory: " + tempDir.getAbsolutePath());
		}
	}

	private class UpdateRepository extends IterateRepository {
		private File outdirectory;
		private String repo;
		private boolean overwrite;
		private DatabaseInformation info;
		private LSHVectorFactory vectorFactory;

		public UpdateRepository(File outdir, String rp, boolean owrite, DatabaseInformation i,
				LSHVectorFactory vFactory) {
			outdirectory = outdir;
			repo = rp;
			overwrite = owrite;
			info = i;
			vectorFactory = vFactory;
		}

		@Override
		protected void process(Program program, TaskMonitor monitor) throws IOException {
			// NOTE: task monitor not used by DescriptionManager
			String md5string = program.getExecutableMD5();
			if ((md5string == null) || (md5string.length() < 10)) {
				Msg.error(this, "Could not get MD5 on file: " + program.getDomainFile().getName());
				return;
			}
			String basename = "update_" + md5string;
			File file = new File(outdirectory, basename);
			if ((!overwrite) && file.exists()) {
				Msg.warn(this,
					"Update file already exists for: " + program.getDomainFile().getName());
				return;
			}
			GenSignatures gensig = new GenSignatures(true);
			try {
				gensig.setVectorFactory(vectorFactory);
				gensig.addExecutableCategories(info.execats);
				gensig.addFunctionTags(info.functionTags);
				gensig.addDateColumnName(info.dateColumnName);
				Msg.info(this, "Generating metadata for: " + program.getDomainFile().getName());
				String path = GenSignatures.getPathFromDomainFile(program);
				gensig.openProgram(program, null, null, null, repo, path);
				gensig.scanFunctionsMetadata(null, null);
				DescriptionManager manager = gensig.getDescriptionManager();
				if (manager.numFunctions() == 0) {
					Msg.warn(this,
						program.getDomainFile().getName() + " contains no functions with bodies");
				}
				try (FileWriter fwrite = new FileWriter(file)) {
					manager.saveXml(fwrite);
				}
			}
			catch (LSHException e) {
				throw new IOException("Program signature generation failure: " + e.getMessage());
			}
		}
	}

	private class SignatureRepository extends IterateRepository {

		private File outdirectory;
		private String repo; // Repository URL to include with signature metadata
		private boolean overwrite; // True if existing signature files should be overwritten
		private DatabaseInformation info; // Database configuration (may affect signature generation)
		private LSHVectorFactory vectorFactory;

		public SignatureRepository(File outdir, String rp, boolean owrite, DatabaseInformation i,
				LSHVectorFactory vFactory) {
			outdirectory = outdir;
			repo = rp;
			overwrite = owrite;
			info = i;
			vectorFactory = vFactory;
		}

		@Override
		protected void process(Program program, TaskMonitor monitor) throws IOException {
			// NOTE: task monitor not used by DescriptionManager
			String md5string = program.getExecutableMD5();
			if ((md5string == null) || (md5string.length() < 10)) {
				Msg.error(this, "Could not get MD5 on file: " + program.getDomainFile().getName());
				return;
			}
			String basename = "sigs_" + md5string;
			File file = new File(outdirectory, basename);
			if ((!overwrite) && file.exists()) {
				Msg.warn(this,
					"Signature file already exists for: " + program.getDomainFile().getName());
				return;
			}
			GenSignatures gensig = new GenSignatures(true);
			try {
				gensig.setVectorFactory(vectorFactory);
				gensig.addExecutableCategories(info.execats);
				gensig.addFunctionTags(info.functionTags);
				gensig.addDateColumnName(info.dateColumnName);
				Msg.info(this, "Generating signatures for: " + program.getDomainFile().getName());
				String path = GenSignatures.getPathFromDomainFile(program);
				gensig.openProgram(program, null, null, null, repo, path);
				FunctionManager fman = program.getFunctionManager();
				Iterator<Function> iterator = fman.getFunctions(true);
				gensig.scanFunctions(iterator, fman.getFunctionCount(), null);
				DescriptionManager manager = gensig.getDescriptionManager();
				if (manager.numFunctions() == 0) {
					Msg.warn(this, program.getDomainFile().getName() +
						" contains no functions with signatures");
					return;
				}
				FileWriter fwrite = new FileWriter(file);
				manager.saveXml(fwrite);
				fwrite.close();
			}
			catch (DecompileException | LSHException e) {
				throw new IOException("Program signature generation failure: " + e.getMessage());
			}
		}
	}
}
