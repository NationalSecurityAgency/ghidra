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
package ghidra.framework.plugintool.util;

import java.util.Map;

import generic.test.TestUtils;
import ghidra.framework.plugintool.Plugin;

/**
 * A builder to allow test writers to easily create a {@link StubPluginDescription}.
 */
public class StubPluginDescriptionBuilder {

	private Class<? extends Plugin> clazz;
	private PluginPackage pluginPackage;
	private PluginStatus status = PluginStatus.RELEASED;
	private String category = "Category";
	private String shortDescription = "Short description";

	public StubPluginDescriptionBuilder(Class<? extends Plugin> clazz,
			PluginPackage pluginPackage) {
		this.clazz = clazz;
		this.pluginPackage = pluginPackage;
	}

	public StubPluginDescriptionBuilder status(PluginStatus pluginStatus) {
		this.status = pluginStatus;
		return this;
	}

	public StubPluginDescriptionBuilder category(String pluginCategory) {
		this.category = pluginCategory;
		return this;
	}

	public StubPluginDescriptionBuilder shortDescription(String description) {
		this.shortDescription = description;
		return this;
	}

	public StubPluginDescription build() {

		// as a convenience for test writers, ensure that the given plugin package is registered
		// with the system
		@SuppressWarnings("unchecked")
		Map<String, PluginPackage> map = (Map<String, PluginPackage>) TestUtils
				.getInstanceField("packageMap", PluginPackage.class);
		map.put(pluginPackage.getName().toLowerCase(), pluginPackage);

		if (shortDescription == null) {
			shortDescription = "Short description for " + clazz.getSimpleName();
		}

		return new StubPluginDescription(clazz, pluginPackage, category, shortDescription, status);
	}
}
