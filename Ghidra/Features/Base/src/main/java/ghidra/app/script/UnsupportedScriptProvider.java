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
package ghidra.app.script;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Pattern;

import generic.jar.ResourceFile;

/**
 * A stub provider for unsupported scripts. These will typically be scripts with supported
 * extensions but unsupported {@link ScriptInfo#AT_RUNTIME} tags.
 */
public class UnsupportedScriptProvider extends GhidraScriptProvider {

	private GhidraScriptProvider baseProvider;

	public UnsupportedScriptProvider() {
		// Necessary for instantiation from the ClassSearcher
	}

	/**
	 * Creates a new {@link UnsupportedScriptProvider} that is derived from the given base provider.
	 * The base provider is any provider with a compatible extension, but without the required
	 * {@link ScriptInfo#AT_RUNTIME} tag.
	 * 
	 * @param baseProvider The base {@link GhidraScriptProvider}
	 */
	public UnsupportedScriptProvider(GhidraScriptProvider baseProvider) {
		this.baseProvider = baseProvider;
	}

	@Override
	public String getDescription() {
		return "<unsupported>";
	}

	@Override
	public String getExtension() {
		return baseProvider.getExtension();
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws GhidraScriptLoadException {
		throw new GhidraScriptLoadException("Script is not supported.");
	}

	@Override
	public void createNewScript(ResourceFile newScript, String category) throws IOException {
		// Do nothing
	}

	@Override
	public String getCommentCharacter() {
		return baseProvider.getCommentCharacter();
	}

	@Override
	public Pattern getBlockCommentStart() {
		return baseProvider.getBlockCommentStart();
	}

	@Override
	public Pattern getBlockCommentEnd() {
		return baseProvider.getBlockCommentEnd();
	}

	@Override
	protected String getCertifyHeaderStart() {
		return baseProvider.getCertifyHeaderStart();
	}

	@Override
	protected String getCertificationBodyPrefix() {
		return baseProvider.getCertificationBodyPrefix();
	}

	@Override
	protected String getCertifyHeaderEnd() {
		return baseProvider.getCertifyHeaderEnd();
	}
}
