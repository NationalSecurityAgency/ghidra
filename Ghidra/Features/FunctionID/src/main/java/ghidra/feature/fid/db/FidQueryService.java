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
package ghidra.feature.fid.db;

import java.io.Closeable;
import java.io.IOException;
import java.util.*;

import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.program.model.lang.Language;
import ghidra.util.exception.VersionException;

/**
 * This object represents a set of open Fid databases appropriate for querying against a
 * particular language.  This object must be closed when it is no longer needed.
 */

public class FidQueryService implements Closeable {
	List<FidDB> fidDbList = new ArrayList<>();
	List<FidQueryCloseListener> listeners = new ArrayList<>();

	FidQueryService(Set<FidFile> fidFiles, Language language, boolean openForUpdate)
			throws VersionException, IOException {
		for (FidFile fidFile : fidFiles) {
			if (fidFile.isActive() && (language == null || fidFile.canProcessLanguage(language))) {
				// NOTE: assumes fidFiles have been pre-checked for version compatibility
				fidDbList.add(fidFile.getFidDB(openForUpdate));
			}
		}
	}

	/**
	 * Adds a listener to be notified when this FidQueryService is closed.
	 * @param listener to be notified when this FidQueryService is closed.
	 */
	public void addCloseListener(FidQueryCloseListener listener) {
		listeners.add(listener);
	}

	/**
	 * Removes the listener to be notified when this FidQueryService is closed.
	 * @param listener to no longer be notified when this FidQueryService is closed.
	 */
	public void removeCloseListener(FidQueryCloseListener listener) {
		listeners.remove(listener);
	}

	/**
	 * Returns a single function record given its id, or null if no such record exists,
	 * searching across all attached databases.
	 * NOTE: function record ids are generated so they are unique across libraries and
	 * databases.
	 * @param functionID the function record primary key id
	 * @return the function record or null if non-existent
	 */
	public FunctionRecord getFunctionByID(long functionID) {
		for (FidDB fidDb : fidDbList) {
			FunctionRecord functionRecord = fidDb.getFunctionByID(functionID);
			if (functionRecord != null) {
				return functionRecord;
			}
		}
		return null;
	}

	/**
	 * Returns true if the relation exists, between a superior (caller) function and a
	 * full hash representing the inferior (callee) function, searching across all
	 * attached databases.
	 * @param superiorFunction the caller function
	 * @param inferiorFunction a hash representing the callee function
	 * @return true if the relation exists
	 */
	public boolean getSuperiorFullRelation(FunctionRecord superiorFunction,
			FidHashQuad inferiorFunction) {
		for (FidDB fidDb : fidDbList) {
			if (fidDb.getSuperiorFullRelation(superiorFunction, inferiorFunction)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns true if the relation exists, between an inferior (callee) function and a
	 * full hash representing the superior (caller) function, searching across all
	 * attached databases.
	 * @param superiorFunction a hash representing the caller function
	 * @param inferiorFunction the callee function
	 * @return true if the relation exists
	 */
	public boolean getInferiorFullRelation(FidHashQuad superiorFunction,
			FunctionRecord inferiorFunction) {
		for (FidDB fidDb : fidDbList) {
			if (fidDb.getInferiorFullRelation(superiorFunction, inferiorFunction)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the library record in which the provided function record resides.
	 * @param functionRecord the function record
	 * @return the library record for that function
	 */
	public LibraryRecord getLibraryForFunction(FunctionRecord functionRecord) {
		for (FidDB fidDb : fidDbList) {
			LibraryRecord libraryRecord = fidDb.getLibraryForFunction(functionRecord);
			if (libraryRecord != null) {
				return libraryRecord;
			}
		}
		return null;
	}

	/**
	 * Returns the first full hash value across all the databases that is greater than or
	 * equal to the provided argument.  Mostly for debug or statistical analysis
	 * @param value the minimum hash value to seek
	 * @return the lowest hash in the databases greater than or equal to value, or null if no such hash
	 */
	public Long findFullHashValueAtOrAfter(long value) {
		Long minimumValue = null;
		for (FidDB fidDb : fidDbList) {
			Long fullHashValue = fidDb.findFullHashValueAtOrAfter(value);
			if (fullHashValue != null) {
				if (minimumValue == null || fullHashValue < minimumValue) {
					minimumValue = fullHashValue;
				}
			}
		}
		return minimumValue;
	}

	/**
	 * Returns all the function records that have the provided specific hash, searching across all
	 * attached databases.
	 * @param hash the hash value
	 * @return a list of function records that match the hash value
	 */
	public List<FunctionRecord> findFunctionsBySpecificHash(long specificHash) {
		ArrayList<FunctionRecord> result = new ArrayList<FunctionRecord>();
		for (FidDB fidDb : fidDbList) {
			List<FunctionRecord> list = fidDb.findFunctionsBySpecificHash(specificHash);
			if (list != null) {
				result.addAll(list);
			}
		}
		return result;
	}

	/**
	 * Returns all the function records that have the provided full hash, searching across all
	 * attached databases.
	 * @param hash the hash value
	 * @return a list of function records that match the hash value
	 */
	public List<FunctionRecord> findFunctionsByFullHash(long fullHash) {
		ArrayList<FunctionRecord> result = new ArrayList<FunctionRecord>();
		for (FidDB fidDb : fidDbList) {
			List<FunctionRecord> list = fidDb.findFunctionsByFullHash(fullHash);
			if (list != null) {
				result.addAll(list);
			}
		}
		return result;
	}

	/**
	 * Searches all databases for functions that match a name substring.
	 * @param name the name substring
	 * @return the functions matching the search (or empty)
	 */
	public List<FunctionRecord> findFunctionsByNameSubstring(String name) {
		ArrayList<FunctionRecord> result = new ArrayList<FunctionRecord>();
		for (FidDB fidDb : fidDbList) {
			List<FunctionRecord> list = fidDb.findFunctionsByNameSubstring(name);
			if (list != null) {
				result.addAll(list);
			}
		}
		return result;
	}

	/**
	 * Searches all databases for functions that match a domain path substring.
	 * @param domainPath the domain path substring
	 * @return the functions matching the search (or empty)
	 */
	public List<FunctionRecord> findFunctionsByDomainPathSubstring(String domainPath) {
		ArrayList<FunctionRecord> result = new ArrayList<FunctionRecord>();
		for (FidDB fidDb : fidDbList) {
			List<FunctionRecord> list = fidDb.findFunctionsByDomainPathSubstring(domainPath);
			if (list != null) {
				result.addAll(list);
			}
		}
		return result;
	}

	/**
	 * Closes this FidQueryService which in turn closes all of its open Fid databases.  It also
	 * notifies any registered listeners that it has been closed.
	 */
	@Override
	public void close() {
		// first copy and reset listeners in case someone tries to remove listener during callback.
		List<FidQueryCloseListener> currentListeners = listeners;
		listeners = new ArrayList<>();
		for (FidQueryCloseListener listener : currentListeners) {
			listener.fidQueryClosed(this);
		}
		listeners.clear();
		for (FidDB fidDb : fidDbList) {
			fidDb.close();
		}
	}

}
