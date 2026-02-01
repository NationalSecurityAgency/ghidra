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
package ghidra.features.bsim.query.description;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import generic.hash.SimpleCRC32;
import ghidra.features.bsim.query.LSHException;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.Msg;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Metadata about a specific executable, as stored in a BSim database
 * There are two basic varieties:
 *   Normal executables, which can be viewed as a container of functions where
 *     each function has a body and an address (and a corresponding feature vector)
 *   Library executables, which contains functions that can only be identified by
 *     name and have no body (or corresponding feature vector)
 */
public class ExecutableRecord implements Comparable<ExecutableRecord> {
	public static final Date EMPTY_DATE = new Date(0);

	// Boolean attributes associated with an ExecutableRecord via its -flags- field
	public static final int ALREADY_STORED = 1;
	public static final int LIBRARY = 2;
	public static final int CATEGORIES_SET = 4;

	// Flags to indicate differences in metadata
	public static final int METADATA_NAME = 1;
	public static final int METADATA_ARCH = 2;
	public static final int METADATA_COMP = 4;
	public static final int METADATA_DATE = 8;
	public static final int METADATA_REPO = 16;
	public static final int METADATA_PATH = 32;
	public static final int METADATA_LIBR = 64;

	private final String md5sum;		// The MD5 hash of the executable 
	private final String executableName;		// The name of the executable
	private final String architecture;	// The architecture on which the executable runs
	private final String compilerName;	// The name of the compiler used to build the executable
	private Date date;					// Date of (ingest)
	private String repository;			// The repository containing the executable
	private String path;				// The path (within the repository) to the executable
	private RowKey rowid;				// The primary database key associated with the executable record
	private int flags;					// Boolean attributes of an executable
	private List<CategoryRecord> usercat; // Categories this executable belongs to
	private int xrefIndex; // Index for cross-referencing this executable from other records

	public static class Update {
		public ExecutableRecord update;
		public boolean name_exec; // Should name be updated
		public boolean architecture; // Should architecture be updated
		public boolean name_compiler;
		public boolean repository;
		public boolean path;
		public boolean date;
		public boolean categories; // True if there are either insertions or deletions
		public List<CategoryRecord> catinsert; // Non-null, if there are only insertions
	}

	/**
	 * Convert a 32-bit integer to hexadecimal ascii representation
	 * @param val is the integer to encode
	 * @param buf accumulates the resulting ascii
	 */
	private static void wordToAscii(int val, StringBuilder buf) {
		for (int i = 28; i >= 0; i -= 4) {
			final int nibble = (val >> i) & 0xf;
			if (nibble < 10) {
				buf.append((char) (nibble + '0'));
			}
			else {
				buf.append((char) (nibble - 10 + 'a'));
			}
		}
	}

	/**
	 * Generate a placeholder md5 string for a library executable based just
	 * on its name and architecture
	 * @param enm is the name of the library
	 * @param arc is the architecture
	 * @return the placeholder md5 String
	 */
	static public String calcLibraryMd5Placeholder(String enm, String arc) {
		int hi = 0xb1b110;
		int lo = 0xfabafaba;
		for (int i = 0; i < enm.length(); ++i) {
			final int feed = lo >>> 24;
			lo = SimpleCRC32.hashOneByte(lo, enm.charAt(i) & 0xff);
			hi = SimpleCRC32.hashOneByte(hi, feed);
		}
		lo ^= 0xf1b1f1b1;
		for (int i = 0; i < arc.length(); ++i) {
			final int feed = lo >>> 24;
			lo = SimpleCRC32.hashOneByte(lo, arc.charAt(i) & 0xff);
			hi = SimpleCRC32.hashOneByte(hi, feed);
		}
		StringBuilder buf = new StringBuilder();
		buf.append("bbbbbbbbaaaaaaaa");
		wordToAscii(hi, buf);
		wordToAscii(lo, buf);
		return buf.toString();
	}

	/**
	 * Constructor for searching within a DescriptionManager
	 * @param md5 is hash of executable being searched for
	 */
	protected ExecutableRecord(String md5) {
		md5sum = md5;
		executableName = "";
		architecture = "";
		compilerName = "";
		rowid = null;
		flags = 0;
		usercat = null;
		xrefIndex = 0;
		repository = null;
		path = null;
		date = EMPTY_DATE;
	}

	/**
	 * Construct a normal (non-library) record.  Fill-in all fields except categories.
	 * Categories are marked as NOT set
	 * @param md5 is the md5 checksum
	 * @param execName is the executable name
	 * @param compilerName is the compiler name
	 * @param architecture is the processor architecture
	 * @param date is the date of ingest (may be null)
	 * @param id is the row id of the record
	 * @param repo is the repository containing the executable (may be null)
	 * @param path is the path to the executable (may be null)
	 */
	public ExecutableRecord(String md5, String execName, String compilerName, String architecture,
			Date date, RowKey id, String repo, String path) {
		this.md5sum = md5;
		this.executableName = execName;
		this.architecture = architecture;
		this.compilerName = compilerName;
		this.rowid = id;
		this.flags = 0;
		this.usercat = null;
		this.xrefIndex = 0;
		setRepository(repo, path);
		setDate(date);
	}

	/**
	 * Construct a normal (non-library) record.  Fill-in all fields.
	 * @param md5 is the md5 checksum
	 * @param enm is the executable name
	 * @param cnm is the compiler name
	 * @param arc is the architecture
	 * @param dt is the date of ingest (may be null)
	 * @param uc is the categories (may be null, categories are considered SET regardless)
	 * @param id is the row id of the record
	 * @param repo is the repository containing the executable (may be null)
	 * @param pth is the path to the executable (may be null)
	 */
	public ExecutableRecord(String md5, String enm, String cnm, String arc, Date dt,
			List<CategoryRecord> uc, RowKey id, String repo, String pth) {
		md5sum = md5;
		executableName = enm;
		architecture = arc;
		compilerName = cnm;
		rowid = id;
		flags = 0;
		xrefIndex = 0;
		setRepository(repo, pth);
		setDate(dt);
		setCategory(uc);
	}

	/**
	 * Constructor for a "library" executable
	 * @param enm is the name of the library
	 * @param arc is the architecture for functions in the library
	 * @param id is the database (row) id of the record (may be null)
	 */
	public ExecutableRecord(String enm, String arc, RowKey id) {
		executableName = enm;
		architecture = arc;
		compilerName = "";
		date = EMPTY_DATE;
		repository = null;		// Not contained in a repository
		path = null;
		rowid = id;
		flags = LIBRARY; // Indicate that this is a library
		md5sum = calcLibraryMd5Placeholder(enm, arc);
		usercat = null;
		xrefIndex = 0;
	}

	/**
	 * Set the repository and path Strings for an executable, replacing
	 * any previous setting. Truncate any trailing slash.
	 * @param repo is (URL) string indicating which repository contains this executable
	 * @param newpath is the path, relative to the repository, to the executable
	 * @throws IllegalArgumentException if invalid repo URL specified
	 */
	protected void setRepository(String repo, String newpath) {
		repository = null;
		if (repo != null) {
			URL ghidraURL;
			try {
				ghidraURL = new URL(repo);
				if (!GhidraURL.isGhidraURL(repo) || (!GhidraURL.isServerRepositoryURL(ghidraURL) &&
					!GhidraURL.isLocalProjectURL(ghidraURL))) {
					throw new IllegalArgumentException("Unsupported repository URL: " + repo);
				}
			}
			catch (MalformedURLException e) {
				throw new IllegalArgumentException("Unsupported repository URL: " + repo, e);
			}
			URL projectURL = GhidraURL.getProjectURL(ghidraURL);
			repository = projectURL.toExternalForm();
		}

		path = newpath;
		if ((path != null) && (path.charAt(path.length() - 1) == '/')) { // No slash at end of path string
			if (path.length() == 1) {
				path = null;
			}
			else {
				path = path.substring(0, path.length() - 1);
			}
		}
		if ((path != null) && (path.charAt(0) == '/')) { // No slash at beginning of path
			if (path.length() == 1) {
				path = null;
			}
			else {
				path = path.substring(1);
			}
		}
	}

	/**
	 * Set the ingest date of the executable
	 * @param dt is the data, which may be null
	 */
	private void setDate(Date dt) {
		if (dt == null) {
			date = EMPTY_DATE;
		}
		else {
			date = dt;
		}
	}

	protected void setRowId(RowKey i) {
		rowid = i;
	}

	protected void setAlreadyStored() {
		flags |= ALREADY_STORED;
	}

	protected void setXrefIndex(int val) {
		xrefIndex = val;
	}

	protected void setCategory(List<CategoryRecord> cats) {
		flags |= CATEGORIES_SET;
		if (cats == null || cats.size() == 0) {
			usercat = null;
			return;
		}
		usercat = cats;
		Collections.sort(usercat); // keep categories sorted, by type, then by category
	}

	protected void cloneCategories(ExecutableRecord op2) {
		flags &= ~CATEGORIES_SET;
		if (op2.categoriesAreSet()) {
			flags |= CATEGORIES_SET;
		}
		if (op2.usercat == null) {
			return;
		}
		usercat = new ArrayList<CategoryRecord>();
		for (int i = 0; i < op2.usercat.size(); ++i) {
			CategoryRecord curRec = op2.usercat.get(i);
			CategoryRecord cloneRec = new CategoryRecord(curRec.getType(), curRec.getCategory());
			usercat.add(cloneRec);
		}
	}

	/**
	 * @return the list of {@link CategoryRecord}s associated with this executable
	 */
	public List<CategoryRecord> getAllCategories() {
		return usercat;
	}

	/**
	 * Return the executable's settings for a specific category type
	 * @param type is the category type
	 * @return the list of settings with this type (or null)
	 */
	public List<String> getCategory(String type) {
		if (usercat == null) {
			return null;
		}
		List<String> res = new ArrayList<String>();
		int min = 0;
		int max = usercat.size() - 1;
		while (min <= max) {
			int mid = (min + max) / 2;
			String curtype = usercat.get(mid).getType();
			int cmp = type.compareTo(curtype);
			if (cmp <= 0) {
				max = mid - 1;
			}
			else {
				min = mid + 1;
			}
		}

		while (min < usercat.size()) {
			CategoryRecord currec = usercat.get(min);
			if (!type.equals(currec.getType())) {
				break;
			}
			min += 1;
			res.add(currec.getCategory());
		}
		return res;
	}

	/**
	 * Determine if an executable has been set with a specific category value
	 * @param type is the type of category to check
	 * @param value is the value to check for
	 * @return true if the executable has that value, false otherwise
	 */
	public boolean hasCategory(String type, String value) {
		if (usercat == null) {
			return false;
		}
		int min = 0;
		int max = usercat.size() - 1;
		while (min <= max) {
			int mid = (min + max) / 2;
			CategoryRecord catrec = usercat.get(mid);
			if (catrec == null) {
				Msg.error(this, "No entry in category list found for index: " + mid +
					" (list size = " + usercat.size() + ")");
				return false;
			}
			String curtype = catrec.getType();
			int cmp = type.compareTo(curtype);
			if (cmp == 0) {
				final int subcmp = value.compareTo(catrec.getCategory());
				if (subcmp < 0) {
					max = mid - 1;
				}
				else if (subcmp > 0) {
					min = mid + 1;
				}
				else {
					return true; // Found match of type and value
				}
			}
			else if (cmp < 0) {
				max = mid - 1;
			}
			else {
				min = mid + 1;
			}
		}

		return false;
	}

	/**
	 * @return the MD5 hash of the executable
	 */
	public String getMd5() {
		return md5sum;
	}

	/**
	 * @return the name of the executable
	 */
	public String getNameExec() {
		return executableName;
	}

	/**
	 * @return the architecture associated with the executable
	 */
	public String getArchitecture() {
		return architecture;
	}

	/**
	 * @return the name of the compiler that built this executable
	 */
	public String getNameCompiler() {
		return compilerName;
	}

	/**
	 * @return the date this executable was ingested into the database
	 */
	public Date getDate() {
		return date;
	}

	/**
	 * @return the URL of the repository containing this executable
	 */
	public String getRepository() {
		return repository;
	}

	/**
	 * @return the (repository relative) path to the executable
	 */
	public String getPath() {
		return path;
	}

	/**
	 * @return true if this executable is a "library" (functions identified only by name)
	 */
	public boolean isLibrary() {
		return ((flags & LIBRARY) != 0);
	}

	/**
	 * @return true if this database record has already been stored in the database
	 */
	public boolean isAlreadyStored() {
		return ((flags & ALREADY_STORED) != 0);
	}

	/**
	 * @return true if categories have been queried in (does not mean that it has any categories)
	 */
	public boolean categoriesAreSet() {
		return ((flags & CATEGORIES_SET) != 0);
	}

	/**
	 * @return the fully formed URL to this executable or null
	 */
	public String getURLString() {
		if (repository == null) {
			return null;
		}
		final StringBuffer buf = new StringBuffer();
		buf.append(repository);
		if (GhidraURL.isLocalGhidraURL(repository)) {
			if (!repository.endsWith("?")) {
				// local URLs add path as a query string
				buf.append("?");
			}
		}
		if (path != null) {
			buf.append('/').append(path);
		}
		buf.append('/').append(executableName);
		return buf.toString();
	}

	/**
	 * Get all the category settings of a specific type in alphabetic order.
	 * Multiple values are returned in a single String separated by ','
	 * @param type is the type of category to retrieve
	 * @return the concatenated list of settings
	 */
	public String getExeCategoryAlphabetic(String type) {
		final List<String> catrecs = getCategory(type);
		if ((catrecs == null) || (catrecs.size() == 0)) {
			return "";
		}
		if (catrecs.size() == 1) {
			return catrecs.get(0);
		}
		// If there are more than one categories they should already be sorted
		final StringBuffer buf = new StringBuffer();
		for (int i = 0; i < 4; ++i) { // Spell out 4 at most
			buf.append(catrecs.get(i));
			if (i + 1 >= catrecs.size()) {
				break;
			}
			if (i < 3) {
				buf.append(',');
			}
		}
		return buf.toString();
	}

	/**
	 * @return the database (row) id of this executable object
	 */
	public RowKey getRowId() {
		return rowid;
	}

	/**
	 * @return the internal cross-referencing index for this executable
	 */
	public int getXrefIndex() {
		return xrefIndex;
	}

	/**
	 * Serialize this executable (meta-data) to an XML stream
	 * @param fwrite is the XML stream
	 * @throws IOException if there are I/O errors writing to the stream
	 */
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("<exe");
		if (isLibrary()) {
			fwrite.append(" library=\"true\"");
		}
		fwrite.append(">\n");
		fwrite.append("  <md5>").append(md5sum).append("</md5>\n");
		fwrite.append("  <name>");
		SpecXmlUtils.xmlEscapeWriter(fwrite, executableName);
		fwrite.append("</name>\n");
		fwrite.append("  <arch>");
		SpecXmlUtils.xmlEscapeWriter(fwrite, architecture);
		fwrite.append("</arch>\n");
		fwrite.append("  <compiler>");
		SpecXmlUtils.xmlEscapeWriter(fwrite, compilerName);
		fwrite.append("</compiler>\n");
		long seconds = date.getTime();
		final long millis = seconds % 1000;
		seconds /= 1000;
		fwrite.append("  <date millis=\"")
				.append(SpecXmlUtils.encodeUnsignedInteger(millis))
				.append("\">");
		fwrite.append(SpecXmlUtils.encodeUnsignedInteger(seconds));
		fwrite.append("</date>\n");
		if (repository != null) {
			fwrite.append("  <repository>");
			SpecXmlUtils.xmlEscapeWriter(fwrite, repository);
			fwrite.append("</repository>\n");
		}
		if (path != null) {
			fwrite.append("  <path>");
			SpecXmlUtils.xmlEscapeWriter(fwrite, path);
			fwrite.append("</path>\n");
		}

		if (usercat != null) {
			for (CategoryRecord element : usercat) {
				element.saveXml(fwrite);
			}
		}
		fwrite.append("</exe>\n");
	}

	/**
	 * Identify whether an md5 string is a placeholder hash
	 * (as generated by {@link ExecutableRecord#calcLibraryMd5Placeholder})
	 * @param md5 is the md5 string
	 * @return true if it is a placeholder, false otherwise
	 */
	public static boolean isLibraryHash(String md5) {
		if (md5.length() != 32) {
			return false;
		}
		return md5.startsWith("bbbbbbbbaaaaaaaa");
	}

	/**
	 * Build a new {@link ExecutableRecord} by deserializing from an XML stream
	 * @param parser is the XML parser
	 * @param man is the DescriptionManager that should hold the new executable
	 * @return the new ExecutableRecord
	 * @throws LSHException if there are inconsistencies in the XML description
	 */
	public static ExecutableRecord restoreXml(XmlPullParser parser, DescriptionManager man)
			throws LSHException {
		final XmlElement el = parser.start("exe");
		final boolean islib = SpecXmlUtils.decodeBoolean(el.getAttribute("library"));
		parser.start("md5");
		final String md5sum = parser.end().getText();
		parser.start("name");
		final String name_exec = parser.end().getText();
		String name_compiler = "";
		String architecture = "";
		long seconds = 0;
		long millis = 0;
		RowKey id = null;
		String repo = null;
		String path = null;
		List<CategoryRecord> cats = null;
		while (parser.peek().isStart()) {
			if (parser.peek().getName().equals("category")) {
				if (cats == null) {
					cats = new ArrayList<CategoryRecord>();
				}
				final CategoryRecord newrec = CategoryRecord.restoreXml(parser);
				cats.add(newrec);
			}
			else {
				final XmlElement subel = parser.start();
				final String nm = subel.getName();
				if (nm.equals("arch")) {
					architecture = parser.end().getText();
				}
				else if (nm.equals("compiler")) {
					name_compiler = parser.end().getText();
				}
				else if (nm.equals("date")) {
					millis = SpecXmlUtils.decodeLong(subel.getAttribute("millis"));
					if ((millis < 0) || (millis > 1000)) {
						millis = 0;
					}
					seconds = SpecXmlUtils.decodeLong(parser.end().getText());
				}
				else if (nm.equals("repository")) {
					repo = parser.end().getText();
				}
				else if (nm.equals("path")) {
					path = parser.end().getText();
				}
				else {
					parser.end();
				}
			}
		}

		parser.end(el);
		ExecutableRecord res;

		if (islib) {
			res = man.newExecutableLibrary(name_exec, architecture, id);
			if ((!res.getMd5().equals(md5sum))) {
				throw new LSHException("Read bad library placeholder md5 for ExecutableRecord");
			}
		}
		else {
			final long date_milli = seconds * 1000 + millis;
			res = man.newExecutableRecord(md5sum, name_exec, name_compiler, architecture,
				new Date(date_milli), repo, path, id);
		}
		res.setCategory(cats);
		return res;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		final ExecutableRecord o = (ExecutableRecord) obj;
		return md5sum.equals(o.md5sum);
	}

	@Override
	public int hashCode() {
		return md5sum.hashCode();
	}

	@Override
	public String toString() {
		// @formatter:off
		return getClass().getSimpleName() + "\n\t" +
		"Executable Name: " + executableName + "\n\t" +
		"Architecture: " + architecture + "\n\t" +
		"Compiler Name: " + compilerName + "\n\t" + 
		"Path: " + path;

		// @formatter:off
	}

	@Override
	public int compareTo(ExecutableRecord o) {
		if (this == o) {
			return 0;
		}
		int comp;
		comp = md5sum.compareTo(o.md5sum);
		return comp;
	}

	/**
	 * Compare just the metadata portion (names and versions) of two ExecutableRecords
	 * We do NOT compare categories as these may not have been read into the object yet
	 * @param o is ExecutableRecord to compare with this
	 * @return bit vector with a 1 bit for every field that differs
	 */
	public int compareMetadata(ExecutableRecord o) {
		int res = 0;
		if (!executableName.equals(o.executableName)) {
			res |= METADATA_NAME;
		}
		if (!architecture.equals(o.architecture)) {
			res |= METADATA_ARCH;
		}
		if ((flags & LIBRARY) != (o.flags & LIBRARY)) {
			res |= METADATA_LIBR;
		}
		if ((flags & LIBRARY)!=0)
		{
			return res;		// If we are comparing libraries, remaining fields aren't compared
		}
		if (!compilerName.equals(o.compilerName)) {
			res |= METADATA_COMP;
		}
		if (!date.equals(o.date)) {
			res |= METADATA_DATE;
		}
		if (repository == null) {
			if (o.repository != null) {
				res |= METADATA_REPO;
			}
		}
		else {
			if (o.repository == null) {
				res |= METADATA_REPO;
			}
			else if (!repository.equals(o.repository)) {
				res |= METADATA_REPO;
			}
		}
		if (path == null) {
			if (o.path != null) {
				res |= METADATA_PATH;
			}
		}
		else {
			if (o.path == null) {
				res |= METADATA_PATH;
			}
			else if (!path.equals(o.path)) {
				res |= METADATA_PATH;
			}
		}
		return res;
	}

	/**
	 * Compare the set of categories that -this- and -op2- belong to
	 * @param op2 is executable to compare with this
	 * @return true if the categories are exactly the same
	 */
	public boolean compareCategory(ExecutableRecord op2) {
		if (usercat == null) {
			if (op2.usercat == null) {
				return true;
			}
			return false;
		}
		if (op2.usercat == null) {
			return false;
		}
		if (usercat.size() != op2.usercat.size()) {
			return false;
		}
		for(int i=0;i<usercat.size();++i) {
			if (!usercat.get(i).equals(op2.usercat.get(i))) {
				return false;
			}
		}
		return true;
	}

	private static List<CategoryRecord> findInsertions(List<CategoryRecord> oldlist,
		List<CategoryRecord> newlist) {
		if (newlist == null && oldlist != null)
		{
			return null;							// Indicate we need to delete
		}
		if (newlist != null && oldlist == null) {
			return newlist;
		}
		final List<CategoryRecord> insert = new ArrayList<CategoryRecord>();
		int i=0;
		int j=0;
		while(i<oldlist.size() || j<newlist.size()) {
			if (j==newlist.size()) {
				return null;
			}
			else if (i==oldlist.size()) {
				insert.add(newlist.get(j));
				j += 1;
			}
			else {
				final CategoryRecord oldcat = oldlist.get(i);
				final CategoryRecord newcat = newlist.get(j);
				final int cmp = newcat.compareTo(oldcat);
				if (cmp < 0) {
					insert.add(newcat);
					j += 1;
				}
				else if (cmp == 0) {
					i += 1;
					j += 1;
				}
				else {
					return null;
				}
			}
		}
		return insert;
	}

	/**
	 * Assuming this is a (possibly) updated variant of another executable metadata record
	 * Prepare an Update record describing the difference between the two records
	 * @param res is the Update record to fill in
	 * @param fromDB is the other ExecutableRecord metadata
	 * @return true if overall there has been an update
	 */
	public boolean diffForUpdate(Update res,ExecutableRecord fromDB) {
		res.name_exec = !executableName.equals(fromDB.executableName);
		res.architecture = !architecture.equals(fromDB.architecture);
		res.name_compiler = !compilerName.equals(fromDB.compilerName);
		if ((repository==null)&&(fromDB.repository==null)) {
			res.repository = false;
		}
		else if ((repository!=null)&&(fromDB.repository!=null)) {
			res.repository = !repository.equals(fromDB.repository);
		}
		else if (repository == null) {
			res.repository = false;
		}
		else {
			res.repository = true;
		}
		if ((path==null)&&(fromDB.path==null)) {
			res.path = false;
		}
		else if ((path!=null)&&(fromDB.path!=null)) {
			res.path = !path.equals(fromDB.path);
		}
		else if (path == null) {
			res.path = false;
		}
		else {
			res.path = true;
		}
		res.date = !date.equals(fromDB.date);
		if (usercat==null && fromDB.usercat == null) {	// Neither has any categories
			res.categories = false;
			res.catinsert = null;
		}
		else { // One of the lists is not null
			res.catinsert = findInsertions(fromDB.usercat, usercat);
			if (res.catinsert == null) {
				res.categories = true;		// Deletions are necessary,
			}
			else if (res.catinsert.size()==0) {	// All categories are the same
				res.categories = false;		// Nothing to change
				res.catinsert = null;
			}
			else {
				res.categories = true;		// There are some insertions to be made
			}
		}

		rowid = fromDB.rowid;
		res.update = this;
		return res.name_exec || res.architecture || res.name_compiler || res.repository || res.path
				|| res.date || res.categories;
	}

	/**
	 * Get the formatted raw executable metadata as a string
	 * @return formatted metadata
	 */
	public String printRaw() {
		StringBuilder buf = new StringBuilder();
		buf.append(md5sum);
		buf.append(' ');
		buf.append(executableName);
		buf.append(' ');
		buf.append(architecture);
		buf.append(' ');
		buf.append(compilerName);
		return buf.toString();
	}
}
