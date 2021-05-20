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

import java.util.*;
import java.util.function.Predicate;

import java.io.File;
import java.net.URI;

import org.apache.commons.io.FilenameUtils;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Registry of {@link SymbolServer} instance creators.
 */
public class SymbolServerInstanceCreatorRegistry {

	private static final SymbolServerInstanceCreatorRegistry instance =
		new SymbolServerInstanceCreatorRegistry();

	/**
	 * A static singleton pre-configured with the default symbol server implementations.
	 * 
	 * @return static singleton {@link SymbolServerInstanceCreatorRegistry} instance.
	 */
	public static SymbolServerInstanceCreatorRegistry getInstance() {
		return instance;
	}

	private final TreeMap<Integer, SymbolServerInstanceCreatorInfo> symbolServerInstanceCreatorsByPriority =
		new TreeMap<>();

	private SymbolServerInstanceCreatorRegistry() {
		registerDefaultSymbolServerInstanceCreators();
	}

	/**
	 * Registers a new SymbolServer implementation so that instances of 
	 * it can be created by the user and saved / restored from preferences.
	 *  
	 * @param priority relative order of precedence of polling this
	 * implementation's predicate to detect the specific SymbolServer
	 * implementation from a locationString.
	 * @param locationStringMatcher predicate that returns true / false if the specified String is
	 * handled by this SymbolServer implementation
	 * @param symbolServerInstanceCreator a method that creates a SymbolServer
	 * instance based on the specified location string and context
	 */
	public void registerSymbolServerInstanceCreator(int priority,
			Predicate<String> locationStringMatcher,
			SymbolServerInstanceCreator symbolServerInstanceCreator) {
		SymbolServerInstanceCreatorInfo symbolServerInstanceCreatorInfo =
			new SymbolServerInstanceCreatorInfo(locationStringMatcher, symbolServerInstanceCreator);

		symbolServerInstanceCreatorsByPriority.put(priority, symbolServerInstanceCreatorInfo);
	}

	/**
	 * Converts a list of symbol server location strings to a list of SymbolServer instances.
	 * 
	 * @param locationStrings list of symbol server location strings
	 * @param symbolServerInstanceCreatorContext a {@link SymbolServerInstanceCreatorContext} 
	 * - see {@link #getContext()} or {@link #getContext(Program)}
	 * @return list of {@link SymbolServer}
	 */
	public List<SymbolServer> createSymbolServersFromPathList(List<String> locationStrings,
			SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext) {
		List<SymbolServer> result = new ArrayList<>();
		for (String locationString : locationStrings) {
			SymbolServer symbolServer =
				newSymbolServer(locationString, symbolServerInstanceCreatorContext);
			if (symbolServer != null) {
				result.add(symbolServer);
			}
		}
		return result;
	}

	/**
	 * Creates a new SymbolServer instance, using the registered SymbolServer types.
	 * 
	 * @param symbolServerLocationString SymbolServer location - see {@link SymbolServer#getName()}
	 * @param symbolServerInstanceCreatorContext a {@link SymbolServerInstanceCreatorContext}
	 * - see {@link #getContext()}
	 * or {@link #getContext(Program)}
	 * @return new SymbolServer instance, or null if bad location string
	 */
	public SymbolServer newSymbolServer(String symbolServerLocationString,
			SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext) {
		return newSymbolServer(symbolServerLocationString, symbolServerInstanceCreatorContext,
			SymbolServer.class);
	}

	/**
	 * Creates a new SymbolServer instance, using the registered SymbolServer types.
	 * 
	 * @param symbolServerLocationString SymbolServer location - see {@link SymbolServer#getName()}
	 * @param symbolServerInstanceCreatorContext a {@link SymbolServerInstanceCreatorContext} 
	 * - see {@link #getContext()}
	 * @param expectedSymbolServerClass expected class of the new symbol server being created
	 * @return new SymbolServer instance, or null if bad location string
	 */
	public <T extends SymbolServer> T newSymbolServer(String symbolServerLocationString,
			SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext,
			Class<T> expectedSymbolServerClass) {
		if (symbolServerLocationString == null || symbolServerLocationString.isBlank()) {
			return null;
		}
		for (SymbolServerInstanceCreatorInfo symbolServerInstanceCreatorInfo : symbolServerInstanceCreatorsByPriority
				.values()) {
			if (symbolServerInstanceCreatorInfo.getLocationStringMatcher()
					.test(symbolServerLocationString)) {
				SymbolServer result =
					symbolServerInstanceCreatorInfo.getSymbolServerInstanceCreator()
							.createSymbolServerFromLocationString(
								symbolServerLocationString, symbolServerInstanceCreatorContext);
				if (result == null) {
					return null;
				}
				if (!expectedSymbolServerClass.isInstance(result)) {
					Msg.debug(this, "SymbolServer location unexpected class type.  Wanted " +
						expectedSymbolServerClass.getName() + ", got " +
						result.getClass().getName());
					return null;
				}
				return expectedSymbolServerClass.cast(result);
			}
		}
		Msg.debug(SymbolServerService.class,
			"Symbol server location [" + symbolServerLocationString + "] not valid, skipping.");
		return null;
	}

	/**
	 * Creates a {@link SymbolServerInstanceCreatorContext} that is not bound to a Program.
	 * 
	 * @return new {@link SymbolServerInstanceCreatorContext}
	 */
	public SymbolServerInstanceCreatorContext getContext() {
		return new SymbolServerInstanceCreatorContext(this);
	}

	/**
	 * Creates a new {@link SymbolServerInstanceCreatorContext} that is bound to a Program.
	 * 
	 * @param program Ghidra program
	 * @return new {@link SymbolServerInstanceCreatorContext}
	 */
	public SymbolServerInstanceCreatorContext getContext(Program program) {
		File exeLocation = new File(FilenameUtils.getFullPath(program.getExecutablePath()));
		return new SymbolServerInstanceCreatorContext(exeLocation, this);
	}

	private void registerDefaultSymbolServerInstanceCreators() {
		registerSymbolServerInstanceCreator(0, DisabledSymbolServer::isDisabledSymbolServerLocation,
			DisabledSymbolServer::createInstance);
		registerSymbolServerInstanceCreator(100, HttpSymbolServer::isHttpSymbolServerLocation,
			(loc, context) -> new HttpSymbolServer(URI.create(loc)));
		registerSymbolServerInstanceCreator(200, SameDirSymbolStore::isSameDirLocation,
			(loc, context) -> new SameDirSymbolStore(context.getRootDir()));
		registerSymbolServerInstanceCreator(300, LocalSymbolStore::isLocalSymbolStoreLocation,
			(loc, context) -> new LocalSymbolStore(new File(loc)));
	}

	/**
	 * Functional interface that creates a new {@link SymbolServer} instance using a 
	 * location string and a context instance.
	 * <p>
	 * See {@link #createSymbolServerFromLocationString(String, SymbolServerInstanceCreatorContext)}
	 */
	public interface SymbolServerInstanceCreator {
		/**
		 * Creates a new {@link SymbolServer} instance using the specified location string
		 * and the context available in the symbolServerInstanceCreatorContext.
		 * 
		 * @param symbolServerLocationString location string
		 * @param symbolServerInstanceCreatorContext context
		 * @return new {@link SymbolServer} instance, null if error
		 */
		SymbolServer createSymbolServerFromLocationString(String symbolServerLocationString,
				SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext);
	}

	private static class SymbolServerInstanceCreatorInfo {
		private Predicate<String> locationStringMatcher;
		private SymbolServerInstanceCreator symbolServerInstanceCreator;

		SymbolServerInstanceCreatorInfo(Predicate<String> locationStringMatcher,
				SymbolServerInstanceCreator symbolServerInstanceCreator) {
			this.locationStringMatcher = locationStringMatcher;
			this.symbolServerInstanceCreator = symbolServerInstanceCreator;
		}

		Predicate<String> getLocationStringMatcher() {
			return locationStringMatcher;
		}

		SymbolServerInstanceCreator getSymbolServerInstanceCreator() {
			return symbolServerInstanceCreator;
		}

	}

}
