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
package pdb.symbolserver;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents the common functionality of different types of symbol servers: querying for
 * files containing symbol information and getting those files.
 * 
 */
public interface SymbolServer {
	/**
	 * Optional add-on interface for {@link SymbolServer}s that flag server types as requiring a
	 * valid context object to be queried for {@link SymbolServer#isValid(TaskMonitor)}
	 */
	interface StatusRequiresContext {
		// empty
	}

	/**
	 * Optional add-on interface for {@link SymbolServer}s that allow their trusted-ness value to
	 * be modified.
	 */
	public interface MutableTrust {

		/**
		 * Sets the trusted attribute of this symbol server.
		 * 
		 * @param isTrusted boolean flag, if true this symbolserver will be marked as trusted
		 */
		void setTrusted(boolean isTrusted);
	}

	/**
	 * Name of the symbol server, suitable to use as the identity of this instance,
	 * and which will allow the SymbolServerInstanceCreatorRegistry to recreate an instance.
	 * 
	 * @return string name
	 */
	String getName();

	/**
	 * Descriptive name of the symbol server, used in UI lists, etc.
	 * 
	 * @return string descriptive name
	 */
	default String getDescriptiveName() {
		return getName();
	}

	/**
	 * Returns true if the symbol server is valid and can be queried.
	 * @param monitor {@link TaskMonitor}
	 * 
	 * @return boolean true if symbol server is working
	 */
	boolean isValid(TaskMonitor monitor);

	/**
	 * Returns true if this {@link SymbolServer} is 'trusted', meaning
	 * it can be searched without security issues / warning the user.
	 * 
	 * @return boolean true if this symbolserver is trusted, false if untrusted 
	 */
	default boolean isTrusted() {
		return true;
	}

	/**
	 * Returns true if the raw filename exists in the symbol server.
	 * 
	 * @param filename raw path filename string
	 * @param monitor {@link TaskMonitor}
	 * @return boolean true if file exists
	 */
	boolean exists(String filename, TaskMonitor monitor);

	/**
	 * Searches for a symbol file on the server.
	 * <p>
	 * HttpSymbolServers only support exact matches, LocalSymbolStores can
	 * possibly have fuzzy matches.
	 * 
	 * @param fileInfo {@link SymbolFileInfo} bag of information about the file to search for
	 * @param findOptions set of {@link FindOption} to control the search.
	 *  See {@link FindOption#NO_OPTIONS} or 
	 *  {@link FindOption#of(FindOption...) FindOptions.of(option1, option2...)}
	 * @param monitor {@link TaskMonitor}
	 * @return list of {@link SymbolFileLocation location information instances} about matches 
	 */
	List<SymbolFileLocation> find(SymbolFileInfo fileInfo, Set<FindOption> findOptions,
			TaskMonitor monitor);

	/**
	 * Returns a wrapped InputStream for the specified raw path filename.
	 * 
	 * @param filename raw path filename
	 * @param monitor {@link TaskMonitor}
	 * @return {@link SymbolServerInputStream} wrapped {@link InputStream}, never null
	 * @throws IOException if error or not found
	 * @throws CancelledException if cancelled
	 */
	SymbolServerInputStream getFileStream(String filename, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Returns a location description string of a specific file contained in this symbol server.
	 * <p>
	 * 
	 * @param filename raw path and name of a file in this server
	 *  (typically from {@link SymbolFileLocation#getPath()}
	 * @return a descriptive string with the 'absolute' location of this file
	 */
	String getFileLocation(String filename);

	/**
	 * Returns the number of configured symbol servers that are considered 'untrusted'.
	 * 
	 * @param symbolServers list of {@link SymbolServer}s
	 * @return number of untrusted symbol servers
	 */
	static int getUntrustedCount(Collection<SymbolServer> symbolServers) {
		return (int) symbolServers.stream().filter(ss -> !ss.isTrusted()).count();
	}

}
