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

import java.util.List;
import java.util.Set;

import java.io.IOException;

import ghidra.util.task.TaskMonitor;

/**
 * A wrapper around a real symbol server that indicates that the symbol server has been disabled.
 * <p>
 * Any find() operations will return an empty list, but file retrieval will still be passed through
 * to the original symbol server instance.
 */
public class DisabledSymbolServer implements SymbolServer {

	private static String DISABLED_PREFIX = "disabled://";

	/**
	 * Predicate that tests if the location string is an instance of a disabled location.
	 * 
	 * @param loc location string
	 * @return boolean true if the string should be handled by the DisabledSymbolServer class
	 */
	public static boolean isDisabledSymbolServerLocation(String loc) {
		return loc.startsWith(DISABLED_PREFIX);
	}

	/**
	 *  Factory method to create new instances from a location string.
	 *  
	 * @param locationString location string 
	 * @param context {@link SymbolServerInstanceCreatorContext}
	 * @return new instance, or null if invalid location string
	 */
	public static SymbolServer createInstance(String locationString,
			SymbolServerInstanceCreatorContext context) {
		SymbolServer delegate =
			context.getSymbolServerInstanceCreatorRegistry()
					.newSymbolServer(locationString.substring(DISABLED_PREFIX.length()), context);
		return (delegate != null) ? new DisabledSymbolServer(delegate) : null;
	}

	private SymbolServer delegate;

	/**
	 * Creates a new instance, wrapping an existing SymbolServer.
	 * 
	 * @param delegate the SymbolServer that is being disabled
	 */
	public DisabledSymbolServer(SymbolServer delegate) {
		this.delegate = delegate;
	}

	/**
	 * Returns the wrapped (disabled) SymbolServer.
	 * 
	 * @return wrapped / disabled SymbolServer
	 */
	public SymbolServer getSymbolServer() {
		return delegate;
	}

	@Override
	public String getName() {
		return DISABLED_PREFIX + delegate.getName();
	}

	@Override
	public String getDescriptiveName() {
		return "Disabled - " + delegate.getDescriptiveName();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) {
		return delegate.isValid(monitor);
	}

	@Override
	public boolean exists(String filename, TaskMonitor monitor) {
		return false;
	}

	@Override
	public List<SymbolFileLocation> find(SymbolFileInfo fileInfo, Set<FindOption> findOptions,
			TaskMonitor monitor) {
		return List.of();
	}

	@Override
	public SymbolServerInputStream getFileStream(String filename, TaskMonitor monitor)
			throws IOException {
		return delegate.getFileStream(filename, monitor);
	}

	@Override
	public String getFileLocation(String filename) {
		return delegate.getFileLocation(filename);
	}

	@Override
	public boolean isLocal() {
		return delegate.isLocal();
	}

	@Override
	public String toString() {
		return String.format("DisabledSymbolServer: [ %s ]", delegate.toString());
	}

}
