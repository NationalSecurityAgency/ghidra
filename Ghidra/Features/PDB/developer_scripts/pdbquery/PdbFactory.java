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
package pdbquery;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Helper class for the PdbQuery set of scripts that allows the PdbQuery scripts to manage the
 * opening, holding open (caching), and closing of PDB files so that multiple user queries can
 * be run against the PDBs.  Without this notion, if a user wanted to query a PDB with multiple
 * runs of a query scripts, each run would have to, once again, open and parse the PDB file
 * that is desired, which could take minutes or longer.
 */
public class PdbFactory {

	private static TreeMap<String, PdbInfo> pdbInfoByFile = new TreeMap<>();
	private static Map<Class<? extends GhidraScript>, PdbInfo> pdbInfoByScriptClass =
		new HashMap<>();

	/**
	 * Opens and retains reference to the PDB file specified.  Must call
	 * {@link #closePdb(GhidraScript, String)} to close the PDB and remove it from the map; can
	 * alternatively use {@link #closeAllPdbs(GhidraScript)} to close all PDBs in the map.
	 * @param script script for which we are working
	 * @param filename name of PDB file to open and load into map
	 * @param monitor task monitor
	 * @return PDB associated with the filename
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issues parsing the PDB
	 */
	public static PdbInfo openPdb(GhidraScript script, String filename, TaskMonitor monitor)
			throws CancelledException, PdbException {
		PdbInfo pdbInfo = pdbInfoByFile.get(filename);
		if (pdbInfo != null) {
			return pdbInfo;
		}

		println(script, "Opening PDB: " + filename);

		try {
			AbstractPdb pdb = PdbParser.parse(filename, new PdbReaderOptions(), monitor);
			PdbIdentifiers identifiers = pdb.getIdentifiers();
			pdb.deserialize();
			PdbReaderMetrics metrics = pdb.getPdbReaderMetrics();
			pdbInfo = new PdbInfo(filename, identifiers, pdb, metrics);
			pdbInfoByFile.put(filename, pdbInfo);
			println(script, "\n" + metrics.getPostProcessingReport());
			return pdbInfo;
		}
		catch (IOException ioe) {
			println(script, ioe.getMessage());
			Msg.debug(null, ioe.getMessage());
		}
		return null;
	}

	/**
	 * Closes and unloads the PDB file from the map.  Not removed from map if IOException.
	 * @param script script for which we are working
	 * @param filename filename of the PDB file
	 * @return true if successfully closed and removed from the map; false if not found in the map
	 * or if problem closing the PDB.
	 */
	public static boolean closePdb(GhidraScript script, String filename) {
		boolean success = closePdbInternal(script, filename);
		if (success) {
			pdbInfoByFile.remove(filename);
		}
		return success;
	}

	/**
	 * Closes and unloads the PDB file from the map.  Not removed from map if IOException.
	 * @param script script for which we are working
	 * @return true if all PDBs were successfully closed and unloaded from the map
	 */
	public static boolean closeAllPdbs(GhidraScript script) {
		boolean allUnloaded = true;
		Iterator<Entry<String, PdbInfo>> iterator = pdbInfoByFile.entrySet().iterator();
		while (iterator.hasNext()) {
			Entry<String, PdbInfo> entry = iterator.next();
			String filename = entry.getKey();
			boolean success = closePdbInternal(script, filename);
			if (success) {
				iterator.remove();
			}
			allUnloaded &= success;
		}
		return allUnloaded;
	}

	private static boolean closePdbInternal(GhidraScript script, String filename) {
		PdbInfo pdbInfo = pdbInfoByFile.get(filename);
		AbstractPdb pdb = pdbInfo.getPdb();
		if (pdb != null) {
			try {
				pdb.close();
				String message = "PDB Closed: " + filename;
				println(script, message);
			}
			catch (IOException ioe) {
				println(script, ioe.getMessage());
				Msg.info(null, ioe.getMessage());
				return false;
			}
			return true;
		}
		return false;
	}

	/**
	 * Returns list of PDB information in alphabetical order by filename.
	 * @return the list
	 */
	public static List<PdbInfo> getPdbInfo() {
		List<PdbInfo> orderedPdbInfo = new ArrayList<>();
		for (String name : pdbInfoByFile.navigableKeySet()) {
			orderedPdbInfo.add(pdbInfoByFile.get(name));
		}
		return orderedPdbInfo;
	}

	/**
	 * Sets the cache PdbInfo value for the class argument
	 * @param clazz the class for which to cache the value
	 * @param pdbInfo the PdbInfo value to cache.
	 */
	public static void setLastPdbInfoByScriptClass(Class<? extends GhidraScript> clazz,
			PdbInfo pdbInfo) {
		pdbInfoByScriptClass.put(clazz, pdbInfo);
	}

	/**
	 * Returns the PdbInfo cached for the class argument.
	 * @param clazz the class of the script used to look up the cached value for return
	 * @return the PdbInfo
	 */
	public static PdbInfo getLastPdbInfoByScriptClass(Class<? extends GhidraScript> clazz) {
		return pdbInfoByScriptClass.get(clazz);
	}

	/**
	 * Method for outputting a message to the console (if script is not null); otherwise outputs
	 * the message to Msg.info().
	 * @param script the script
	 * @param message the message to output to the console
	 */
	private static void println(GhidraScript script, String message) {
		if (script != null) {
			script.println(message);
		}
		else {
			Msg.info(PdbFactory.class, message);
		}
	}

	/**
	 * Information about a PDB used for specifying and uniquely identifying a PDB along with the
	 * parsed PDB itself and the PDB parsing metrics generated during the parse.
	 */
	public static class PdbInfo {
		private String filename; // absolute pathname
		private PdbIdentifiers identifiers;
		private AbstractPdb pdb;
		private PdbReaderMetrics metrics;

		/**
		 * Constructor.
		 * @param filename PDB filename in absolute pathname format
		 * @param identifiers identifiers used to help identify versions of the PDB
		 * @param pdb the parsed PDB
		 * @param metrics the PDB metrics generated when the PDB was opened and parsed
		 */
		PdbInfo(String filename, PdbIdentifiers identifiers, AbstractPdb pdb,
				PdbReaderMetrics metrics) {
			this.filename = filename;
			this.identifiers = identifiers;
			this.pdb = pdb;
			this.metrics = metrics;
		}

		/**
		 * Returns the PDB filename in absolute path format
		 * @return the filename
		 */
		public String getFilename() {
			return filename;
		}

		/**
		 * Returns the parsed PDB
		 * @return the parsed PDB
		 */
		public AbstractPdb getPdb() {
			return pdb;
		}

		/**
		 * Returns PDB identifiers that help specify its version
		 * @return the identifiers
		 */
		public PdbIdentifiers getIdentifiers() {
			return identifiers;
		}

		/**
		 * Returns the metrics generated during PDB parsing
		 * @return the metrics
		 */
		public PdbReaderMetrics getPdbReaderMetrics() {
			return metrics;
		}

		@Override
		// The PDB and parsing metrics are purposefully not included in this output.
		public String toString() {
			return filename + "; " + identifiers;
		}

	}
}
