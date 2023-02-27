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
package ghidra.framework.model;

import ghidra.framework.options.Options;

/**
 * {@link DefaultLaunchMode} provides an {@link Options} value which indicates how a default tool
 * launch should be performed.
 */
public enum DefaultLaunchMode {

	REUSE_TOOL("Reuse acceptable running tool"),
	NEW_TOOL("Launch new default tool");

	public static DefaultLaunchMode DEFAULT = NEW_TOOL;

	private String str;

	private DefaultLaunchMode(String str) {
		this.str = str;
	}

	@Override
	public String toString() {
		return str;
	}

}
