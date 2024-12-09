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

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.program.model.address.Address;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Container for metadata about executables (ExecutableRecord),
 * functions (FunctionDescription) and their associated signatures (SignatureRecord)
 * Generally holds sets of functions that are either being inserted into
 * are queried from a BSim database
 */
public class DescriptionManager {
	public static final int LAYOUT_VERSION = 5;	// This versions the XML serialization of the objects put in a DescriptionManager											

	private TreeSet<FunctionDescription> funcrec;	// Functions in this container (sort by exe,name,address)
	private TreeSet<ExecutableRecord> exerec;		// Executables in this container (sort by md5)
	private TreeMap<RowKey, ExecutableRecord> rowCache;	// Alternate index into executables via row id
	private short major; 			// Major version of decompiler used to generate SignatureRecords
	private short minor; 			// Minor version
	private int settings; 			// Settings for signature generation (of functions in this container)

	public DescriptionManager() {
		funcrec = new TreeSet<>();
		exerec = new TreeSet<>();
		rowCache = null;
	}

	/**
	 * Set the version number of the decompiler used to generate SignatureRecords
	 * for this container
	 * @param maj is the major number
	 * @param min is the minor
	 */
	public void setVersion(short maj, short min) {
		major = maj;
		minor = min;
	}

	/**
	 * Establish the particular settings of the signature strategy used to
	 * generate SignatureRecords for this container
	 * @param set is the encoded bit-field of settings
	 */
	public void setSettings(int set) {
		settings = set;
	}

	/**
	 * @return the major version number of the decompiler used for signatures
	 */
	public short getMajorVersion() {
		return major;
	}

	/**
	 * @return the minor version number of the decompiler used for signatures
	 */
	public short getMinorVersion() {
		return minor;
	}

	/**
	 * @return the settings of the signature strategy used for this container
	 */
	public int getSettings() {
		return settings;
	}

	/**
	 * Set the categories associated with a particular executable.
	 * This replaces any existing categories
	 * @param erec is the ExecutableRecord to set
	 * @param cats is the list of categories (CategoryRecord), may be null
	 */
	public void setExeCategories(ExecutableRecord erec, List<CategoryRecord> cats) {
		erec.setCategory(cats);
	}

	/**
	 * Associate a database id with a particular executable
	 * @param erec is the ExecutableRecord
	 * @param id is the database (row) id
	 */
	public void setExeRowId(ExecutableRecord erec, RowKey id) {
		erec.setRowId(id);
	}

	/**
	 * Mark that an executable has (already) been stored in the database
	 * @param erec is the ExecutableRecord
	 */
	public void setExeAlreadyStored(ExecutableRecord erec) {
		erec.setAlreadyStored();
	}

	/**
	 * Associate a signature's id with a particular function
	 * @param frec is the FunctionDescription
	 * @param id is the signature's database id
	 */
	public void setSignatureId(FunctionDescription frec, long id) {
		frec.setVectorId(id);
	}

	/**
	 * Associate a database id with a particular SignatureRecord
	 * @param sigrec is the SignatureRecord
	 * @param id is the signature's database id
	 */
	public void setSignatureId(SignatureRecord sigrec, long id) {
		sigrec.setVectorId(id);
	}

	/**
	 * Associate a database id with a particular function
	 * @param fd is the FunctionDescription
	 * @param id is the database (row) id
	 */
	public void setFunctionDescriptionId(FunctionDescription fd, RowKey id) {
		fd.setId(id);
	}

	/**
	 * Associate function "tags" or attributes with a specific function
	 * @param fd is the FunctionDescription
	 * @param fl is the encoded bitfield of attributes
	 */
	public void setFunctionDescriptionFlags(FunctionDescription fd, int fl) {
		fd.setFlags(fl);
	}

	public TreeSet<ExecutableRecord> getExecutableRecordSet() {
		return exerec;
	}

	/**
	 * Clear out all functions from the container, but leave the executables
	 */
	public void clearFunctions() {
		funcrec.clear();
	}

	/**
	 * Reset to a completely empty container
	 */
	public void clear() {
		clearFunctions();
		major = 0;
		minor = 0;
		settings = 0;
		exerec.clear();
		rowCache = null;
	}

	/**
	 * @return the number of executables described by this container
	 */
	public int numExecutables() {
		return exerec.size();
	}

	/**
	 * @return the number of functions described by this container
	 */
	public int numFunctions() {
		return funcrec.size();
	}

	/**
	 * Allocate a new function in the container
	 * @param fnm is the name of the new function
	 * @param address is the address (offset) of the function
	 * @param erec is the executable containing the function
	 * @param spaceid the id of the address space containing the function
	 * @return the new FunctionDescription
	 */
	public FunctionDescription newFunctionDescription(String fnm, int spaceid, long address,
			ExecutableRecord erec) {
		FunctionDescription newfunc = new FunctionDescription(erec, fnm, spaceid, address);
		if (!funcrec.add(newfunc)) {
			newfunc = funcrec.floor(newfunc);
		}
		return newfunc;
	}

	/**
	 * Create a new executable record, which should be identified uniquely
	 * identified via its md5sum
	 * 
	 * @param md5 is the MD5 hash of the executable
	 * @param enm is the name of the executable
	 * @param cnm is the name of the compiler used to build the executable
	 * @param arc is the architecture of the executable
	 * @param dt is the date (of ingest)
	 * @param repo is the repository containing the executable
	 * @param path is the path (within the repo) to the executable
	 * @param id is the database (row) is associated with the executable (may be null)
	 * @return the new ExecutableRecord object
	 * @throws LSHException if attributes are invalid, or the executable 
	 *     already exists with different metadata
	 */
	public ExecutableRecord newExecutableRecord(String md5, String enm, String cnm, String arc,
			Date dt, String repo, String path, RowKey id) throws LSHException {
		if (md5.length() != 32) {
			throw new LSHException("MD5 field must be exactly 32 hex characters");
		}
		ExecutableRecord newexe = new ExecutableRecord(md5, enm, cnm, arc, dt, id, repo, path);
		if (!exerec.add(newexe)) {
			ExecutableRecord oldexe = exerec.floor(newexe);
			if (oldexe.compareMetadata(newexe) != 0) {
				throw new LSHException("Duplicate md5 hash, different metadata");
			}
			if ((oldexe.getRowId() != null) && (id != null) && (!oldexe.getRowId().equals(id))) {
				throw new LSHException("Overwriting existing executable id");
			}
			newexe = oldexe;
		}
		return newexe;
	}

	/**
	 * Create a new "library" executable in the container.
	 * Functions in this container (will) have no body or address
	 * @param enm is the name of the library
	 * @param arc is the architecture of the library
	 * @param id is the database id associated with the library (may be null)
	 * @return the new ExecutableRecord object
	 * @throws LSHException if attributes are invalid or the
	 *   library already exists with different metadata
	 */
	public ExecutableRecord newExecutableLibrary(String enm, String arc, RowKey id)
			throws LSHException {
		ExecutableRecord newexe = new ExecutableRecord(enm, arc, id);
		if (!exerec.add(newexe)) { // Check for duplicate executable
			ExecutableRecord oldexe = exerec.floor(newexe);
			if (oldexe.compareMetadata(newexe) != 0) {
				throw new LSHException("Duplicate md5 hash, different metadata");
			}
			if ((oldexe.getRowId() != null) && (id != null) && (!oldexe.getRowId().equals(id))) {
				throw new LSHException("Overwriting existing executable id");
			}
			newexe = oldexe;
		}
		return newexe;
	}

	/**
	 * Transfer decompiler and signature settings into this container
	 * @param op2 is the container to transfer from
	 */
	public void transferSettings(DescriptionManager op2) {
		major = op2.major;
		minor = op2.minor;
		settings = op2.settings;
	}

	/**
	 * Transfer an executable from another container into this container
	 * @param erec is the ExecutableRecord from the other container
	 * @return the new transferred ExecutableRecord
	 * @throws LSHException if the executable already exists with different metadata
	 */
	public ExecutableRecord transferExecutable(ExecutableRecord erec) throws LSHException {
		RowKey id = erec.getRowId();

		ExecutableRecord res;
		if (erec.isLibrary()) {
			res = newExecutableLibrary(erec.getNameExec(), erec.getArchitecture(), id);
		}
		else {
			res = newExecutableRecord(erec.getMd5(), erec.getNameExec(), erec.getNameCompiler(),
				erec.getArchitecture(), (Date) erec.getDate().clone(), erec.getRepository(),
				erec.getPath(), id);
		}
		res.cloneCategories(erec);
		return res;
	}

	/**
	 * Transfer a function from another container into this container
	 * @param fdesc is the FunctionDescription to transfer
	 * @param transsig is true if the SignatureRecord should be transferred as well
	 * @return the new transferred FunctionDescription
	 * @throws LSHException if the function already exists with different metadata
	 */
	public FunctionDescription transferFunction(FunctionDescription fdesc, boolean transsig)
			throws LSHException {
		ExecutableRecord erec = transferExecutable(fdesc.getExecutableRecord());
		FunctionDescription res =
			newFunctionDescription(fdesc.getFunctionName(),fdesc.getSpaceID(), fdesc.getAddress(), erec);
		res.setVectorId(fdesc.getVectorId());
		res.setFlags(fdesc.getFlags());
		SignatureRecord srec = fdesc.getSignatureRecord();
		if (transsig && (srec != null)) {
			SignatureRecord sigclone = newSignature(srec.getLSHVector(), srec.getCount());
			attachSignature(res, sigclone);
		}
		return res;
	}

	/**
	 * Generate a map from (row) id to function, for all functions in this container
	 * @param funcmap is the map to populate
	 */
	public void generateFunctionIdMap(Map<RowKey, FunctionDescription> funcmap) {
		for (FunctionDescription func : funcrec) {
			funcmap.put(func.getId(), func);
		}
	}

	/**
	 * Generate a SignatureRecord given a specific feature vector
	 * @param vec is the feature vector (LSHVector)
	 * @param count is a count of functions sharing this feature vector
	 * @return the new SignatureRecord
	 */
	public SignatureRecord newSignature(LSHVector vec, int count) {
		SignatureRecord srec = new SignatureRecord(vec);
		srec.setCount(count);
		return srec;
	}

	/**
	 * Parse a signature (SignatureRecord) from an XML stream
	 * @param parser is the XML parser
	 * @param vectorFactory is the factory used to generate the underlying feature vector
	 * @param count is the count of functions sharing the feature vector
	 * @return the new SignatureRecord
	 */
	public SignatureRecord newSignature(XmlPullParser parser, LSHVectorFactory vectorFactory,
			int count) {
		LSHVector res = vectorFactory.restoreVectorFromXml(parser);
		SignatureRecord srec = new SignatureRecord(res);

		srec.setCount(count);
		return srec;
	}

	/**
	 * Associate a signature with a specific function
	 * @param fd is the FunctionDescription
	 * @param srec is the SignatureRecord
	 */
	public void attachSignature(FunctionDescription fd, SignatureRecord srec) {
		fd.setSignatureRecord(srec);
		setSignatureId(fd, srec.getVectorId());
	}

	/**
	 * Mark a parent/child relationship between to functions
	 * @param src is the parent FunctionDescription
	 * @param dest is the child FunctionDescription
	 * @param lhash is a hash indicating where in -src- the call to -dest- is made
	 */
	public void makeCallgraphLink(FunctionDescription src, FunctionDescription dest, int lhash) {
		src.insertCall(dest, lhash);
	}

	/**
	 * Lookup an executable in the container via md5
	 * @param md5 is the md5 to search for
	 * @return return the matching ExecutableRecord
	 * @throws LSHException if the executable cannot be found
	 */
	public ExecutableRecord findExecutable(String md5) throws LSHException {
		ExecutableRecord templ = new ExecutableRecord(md5);
		ExecutableRecord res = exerec.floor(templ);
		if (res != null && res.getMd5().equals(md5)) {
			return res;
		}
		throw new LSHException("Unable to find executable");
	}

	/**
	 * Search for executable based an name, and possibly other qualifying information.
	 * This is relatively inefficient as it just iterates through the list.
	 * @param name is the name that the executable must match
	 * @param arch is null or must match the executable's architecture string
	 * @param comp is null or must match the executable's compiler string
	 * @return the matching executable
	 * @throws LSHException if a matching executable doesn't exist
	 */
	public ExecutableRecord findExecutable(String name, String arch, String comp)
			throws LSHException {
		if (StringUtils.isEmpty(arch)) {
			arch = null;
		}
		if (StringUtils.isEmpty(comp)) {
			comp = null;
		}
		for (ExecutableRecord erec : exerec) {
			if (!erec.getNameExec().equals(name)) {
				continue;
			}
			if (arch != null && !erec.getArchitecture().equals(arch)) {
				continue;
			}
			if (comp != null && !erec.getNameCompiler().equals(comp)) {
				continue;
			}
			return erec;
		}
		throw new LSHException("Unable to find executable");
	}

	/**
	 * Find a function (within an executable) by its name and address (both must be provided)
	 * If the request function does not exist, an exception is thrown
	 * @param fname - the name of the function
	 * @param address - the address of the function
	 * @param exe - the ExecutableRecord containing the function
	 * @return the FunctionDescription
	 * @throws LSHException if a matching function does not exist
	 */
	public FunctionDescription findFunction(String fname, int spaceid, long address, ExecutableRecord exe)
			throws LSHException {
		FunctionDescription fdesc = new FunctionDescription(exe, fname, spaceid, address);

		FunctionDescription res = funcrec.floor(fdesc);
		if (res == null || (!res.equals(fdesc))) {
			throw new LSHException("Unable to find FunctionDescription");
		}
		return res;
	}

	/**
	 * Find a function within an executable by name. The name isn't guaranteed to be unique. If there
	 * are more than one, the first in address order is returned. If none are found, null is returned
	 * @param fname is the name of the function to match
	 * @param exe is the ExecutableRecord containing the function
	 * @return a FunctionDescription or null 
	 */
	public FunctionDescription findFunctionByName(String fname, ExecutableRecord exe) {
		FunctionDescription fdesc = new FunctionDescription(exe, fname, 0, 0);
		FunctionDescription res = funcrec.ceiling(fdesc);
		if (res == null || !fname.equals(res.getFunctionName()) ||
			!res.getExecutableRecord().equals(exe)) {
			return null;
		}
		return res;
	}

	/**
	 * Find a function (within an executable) by its name and address (both must be provided)
	 * If the function doesn't exist, null is returned, no exception is thrown
	 * @param fname - the name of the function
	 * @param address - the address of the function
	 * @param exe - the executable (possibly) containing the function
	 * @return a FunctionDescription or null
	 */
	public FunctionDescription containsDescription(String fname, Address address,
			ExecutableRecord exe) {
		FunctionDescription fdesc = new FunctionDescription(exe, fname, address.getAddressSpace().getSpaceID(), address.getOffset());
		FunctionDescription res = funcrec.floor(fdesc);
		if (res == null || (!res.equals(fdesc))) {
			return null;
		}
		return res;
	}

	/**
	 * Generate an iterator over all functions belonging to a specific executable
	 * @param exe is the specific executable
	 * @return iterator over all functions in -exe-
	 */
	public Iterator<FunctionDescription> listFunctions(ExecutableRecord exe) {
		ExecutableRecord startexe = exerec.floor(exe);
		ExecutableRecord endexe = exerec.higher(exe);
		if (startexe == null) {
			return null;
		}
		FunctionDescription startfunc = new FunctionDescription(startexe, "", 0, 0);
		startfunc = funcrec.ceiling(startfunc);
		if (startfunc == null) { // No functions in exe or after
			startfunc = funcrec.last();
			return funcrec.subSet(startfunc, startfunc).iterator();
		}
		FunctionDescription endfunc = null;
		if (endexe != null) {
			endfunc = new FunctionDescription(endexe, "", 0, 0);
			endfunc = funcrec.ceiling(endfunc);
		}
		if (endfunc == null) {
			// executable is last and has no functions
			return funcrec.tailSet(startfunc).iterator();
		}
		return funcrec.subSet(startfunc, endfunc).iterator();
	}

	/**
	 * @return an iterator over all functions in the container
	 */
	public Iterator<FunctionDescription> listAllFunctions() {
		return funcrec.iterator();
	}

	/**
	 * Using the standard exe-md5, function name, address sorting, return an
	 * iterator over all functions starting with the first function after
	 * an indicated -func-
	 * @param func is FunctionDescription indicating where the iterator should start (after)
	 * @return the new iterator
	 */
	public Iterator<FunctionDescription> listFunctionsAfter(FunctionDescription func) {
		return funcrec.tailSet(func, false).iterator();
	}

	/**
	 * Create an internal map entry from a database id to an executable
	 * @param erec is the ExecutableRecord
	 * @param rowKey is the database (row) id
	 */
	public void cacheExecutableByRow(ExecutableRecord erec, RowKey rowKey) {
		if (rowCache == null) {
			rowCache = new TreeMap<>();
		}
		rowCache.put(rowKey, erec);
	}

	/**
	 * Look up an executable via database id. This uses an internal map which
	 * must have been explicitly populated via cacheExecutableByRow
	 * @param rowKey is the database (row) id to lookup
	 * @return the associated ExecutableRecord or null if not found
	 */
	public ExecutableRecord findExecutableByRow(RowKey rowKey) {
		if (rowCache == null) {
			return null;
		}
		return rowCache.get(rowKey);
	}

	/**
	 * Assign an internal id to all executables for purposes of cross-referencing in XML
	 * Indices are assigned in order starting at 1 (0 indicates an index has NOT been assigned)
	 */
	public void populateExecutableXref() {
		if (exerec.isEmpty()) {
			return;
		}
		if (exerec.first().getXrefIndex() == 1) {
			return; // Already been populated
		}
		int xrefIndex = 1;
		for (ExecutableRecord exe : exerec) {
			exe.setXrefIndex(xrefIndex);
			xrefIndex += 1;
		}
	}

	/**
	 * For every ExecutableRecord in this container, if it is also in {@code manage},
	 * copy the xrefValue from the {@code manage} version, otherwise 
	 * set the xrefValue to zero
	 * @param manage is the other container match from
	 */
	public void matchAndSetXrefs(DescriptionManager manage) {
		TreeSet<ExecutableRecord> manageSet = manage.exerec;
		for (ExecutableRecord currentRecord : exerec) {
			ExecutableRecord match = manageSet.floor(currentRecord);
			if (match != null && match.getMd5().equals(currentRecord.getMd5())) {
				currentRecord.setXrefIndex(match.getXrefIndex());
			}
			else {
				currentRecord.setXrefIndex(0);		// Mark as having no match in manage
			}
		}
	}

	/**
	 * Assign an internal id to all executables and also create a map from id to executable.
	 * As with {@link DescriptionManager#populateExecutableXref},
	 * ids are assigned in order starting at 1
	 * @return the populated Map object
	 */
	public Map<Integer, ExecutableRecord> generateExecutableXrefMap() {
		TreeMap<Integer, ExecutableRecord> treeMap = new TreeMap<>();
		int xrefIndex = 1;
		for (ExecutableRecord exe : exerec) {
			exe.setXrefIndex(xrefIndex);
			treeMap.put(xrefIndex, exe);
			xrefIndex += 1;
		}
		return treeMap;
	}

	/**
	 * Override the repository setting of every executable in this manager
	 * 
	 * @param repo is the repository string to override with
	 * @param path is the path string to override with
	 */
	public void overrideRepository(String repo, String path) {
		for (ExecutableRecord element : exerec) {
			element.setRepository(repo, path);
		}
	}

	/**
	 * Serialize the entire container to an XML stream
	 * @param fwrite is the stream to write to
	 * @throws IOException if there are problems writing to the stream
	 */
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("<description");
		fwrite.append(" layout_version=\"").append(Integer.toString(LAYOUT_VERSION)).append('\"');
		if (major != 0) {
			fwrite.append(" major=\"").append(Short.toString(major)).append('\"');
			fwrite.append(" minor=\"").append(Short.toString(minor)).append('\"');
		}
		if (settings != 0) {
			fwrite.append(" settings=\"0x").append(Integer.toHexString(settings)).append('\"');
		}
		fwrite.append(">\n");
		ExecutableRecord curexe = null;
		for (FunctionDescription fdesc : funcrec) {
			if ((curexe == null) || (0 != fdesc.getExecutableRecord().compareTo(curexe))) {
				if (curexe != null) {
					fwrite.append("</execlist>\n");
				}
				curexe = fdesc.getExecutableRecord();
				fwrite.append("<execlist>\n");
				curexe.saveXml(fwrite);
			}
			fdesc.sortCallgraph();
			fdesc.saveXml(fwrite);
		}
		if (curexe != null) {
			fwrite.append("</execlist>\n");
		}
		fwrite.append("</description>\n");
	}

	/**
	 * Reconstruct a container by deserializing an XML stream
	 * @param parser is the XML parser
	 * @param vectorFactory is the factory to use for building feature vectors
	 * @throws LSHException if there are inconsistencies in the XML
	 */
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		major = 0;
		minor = 0;
		settings = 0;
		int layout_version = 0;
		XmlElement el = parser.start("description");
		if (el.hasAttribute("layout_version")) {
			layout_version = SpecXmlUtils.decodeInt(el.getAttribute("layout_version"));
		}
		if (layout_version < LAYOUT_VERSION) {
			throw new LSHException("Old XML layout is no longer supported");
		}
		if (layout_version > LAYOUT_VERSION) {
			throw new LSHException("XML layout for newer version of BSIM");
		}
		if (el.hasAttribute("major")) {
			major = (short) SpecXmlUtils.decodeInt(el.getAttribute("major"));
			minor = (short) SpecXmlUtils.decodeInt(el.getAttribute("minor"));
		}
		if (el.hasAttribute("settings")) {
			settings = SpecXmlUtils.decodeInt(el.getAttribute("settings"));
		}
		while (parser.peek().isStart()) {
			parser.start("execlist");
			ExecutableRecord erec = ExecutableRecord.restoreXml(parser, this);
			while (parser.peek().isStart()) {
				FunctionDescription.restoreXml(parser, vectorFactory, this, erec);
			}
			parser.end();
		}
		parser.end();
	}
}
