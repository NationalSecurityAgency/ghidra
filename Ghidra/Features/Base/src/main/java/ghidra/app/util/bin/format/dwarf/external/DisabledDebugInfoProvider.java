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
package ghidra.app.util.bin.format.dwarf.external;

import ghidra.util.task.TaskMonitor;

/**
 * Wrapper around a DebugInfoProvider that prevents it from being queried, but retains it in the
 * configuration list.
 */
public class DisabledDebugInfoProvider implements DebugInfoProvider {
	private static String DISABLED_PREFIX = "disabled://";

	/**
	 * Predicate that tests if the name string is an instance of a disabled name.
	 * 
	 * @param name string
	 * @return boolean true if the string should be handled by the DisabledSymbolServer class
	 */
	public static boolean matches(String name) {
		return name.startsWith(DISABLED_PREFIX);
	}

	/**
	 *  Factory method to create new instances from a name string.
	 *  
	 * @param name string, earlier returned from {@link #getName()}
	 * @param context {@link DebugInfoProviderCreatorContext} to allow accessing information outside
	 * of the name string that might be needed to create a new instance
	 * @return new instance, or null if invalid name string
	 */
	public static DebugInfoProvider create(String name, DebugInfoProviderCreatorContext context) {
		String delegateName = name.substring(DISABLED_PREFIX.length());
		DebugInfoProvider delegate = context.registry().create(delegateName, context);
		return (delegate != null) ? new DisabledDebugInfoProvider(delegate) : null;
	}

	private DebugInfoProvider delegate;

	public DisabledDebugInfoProvider(DebugInfoProvider delegate) {
		this.delegate = delegate;
	}

	@Override
	public String getName() {
		return DISABLED_PREFIX + delegate.getName();
	}

	@Override
	public String getDescriptiveName() {
		return "Disabled - " + delegate.getDescriptiveName();
	}

	public DebugInfoProvider getDelegate() {
		return delegate;
	}

	@Override
	public DebugInfoProviderStatus getStatus(TaskMonitor monitor) {
		return DebugInfoProviderStatus.UNKNOWN;
	}

}
