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
package ghidra.base.help;

import java.net.URL;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.help.HelpSet;
import javax.help.HelpSetException;

import docking.help.GHelpClassLoader;
import docking.help.HelpManager;
import generic.jar.ResourceFile;
import generic.theme.*;
import ghidra.framework.Application;
import ghidra.util.Msg;
import help.HelpService;
import resources.ResourceManager;

/**
 * Ghidra's help service.   This class knows how to find help for the various modules that 
 * make up Ghidra.
 */
public class GhidraHelpService extends HelpManager {

	/**
	 * The hardcoded value to use for all HelpSet 'home id' values.  Subclasses may change this 
	 * value by overriding {@link #getHomeId()}.
	 */
	private static final String GHIDRA_HOME_ID = "Misc_Ghidra_Help_Contents";

	private static final String MASTER_HELP_SET_HS = "Base_HelpSet.hs";
	private ThemeListener listener = new HelpThemeListener();

	public static void install() {
		try {
			new GhidraHelpService();
		}
		catch (HelpSetException e) {
			Msg.error(GhidraHelpService.class, "Unable to load Ghidra help", e);
		}
	}

	private GhidraHelpService() throws HelpSetException {
		super(findMasterHelpSetUrl());
		loadHelpSets();
		registerHelp();
		Gui.addThemeListener(listener);
	}

	private static URL findMasterHelpSetUrl() {

		GHelpClassLoader helpClassLoader = new GHelpClassLoader(null);
		URL url = HelpSet.findHelpSet(helpClassLoader, MASTER_HELP_SET_HS);
		if (url != null) {
			return url;
		}

		Msg.error(GhidraHelpService.class,
			"Failed to locate the primary Help Set.  Try building help to resolve the issue");
		return ResourceManager.getResource("help/" + HelpService.DUMMY_HELP_SET_NAME);
	}

	@Override
	protected String getHomeId() {
		return GHIDRA_HOME_ID;
	}

	private void loadHelpSets() {

		Map<ResourceFile, Set<URL>> helpSetsByModule = findHelpSetsByModule();
		Set<Entry<ResourceFile, Set<URL>>> entries = helpSetsByModule.entrySet();
		for (Entry<ResourceFile, Set<URL>> entry : entries) {
			ResourceFile module = entry.getKey();
			Set<URL> moduleHelpSets = entry.getValue();
			for (URL url : moduleHelpSets) {
				try {
					addHelpSet(url, new GHelpClassLoader(module));
				}
				catch (HelpSetException e) {
					Msg.error(this, "Unexpected Exception Loading HelpSet: " + e.getMessage(), e);
				}
			}
		}
	}

	private Map<ResourceFile, Set<URL>> findHelpSetsByModule() {
		Set<URL> allHelpSets = ResourceManager.getResources("help", "hs");
		Collection<ResourceFile> moduleRoots = Application.getModuleRootDirectories();
		Map<ResourceFile, Set<URL>> helpSetsByModule = mapHelpToModule(moduleRoots, allHelpSets);
		return helpSetsByModule;
	}

	private Map<ResourceFile, Set<URL>> mapHelpToModule(Collection<ResourceFile> moduleRoots,
			Set<URL> allHelpSets) {
		Map<ResourceFile, Set<URL>> results = new HashMap<>();
		for (ResourceFile module : moduleRoots) {
			Set<URL> help = allHelpSets.stream()
					.map(Optional::ofNullable)
					.filter(Optional::isPresent)
					.map(Optional::get)
					.filter(url -> url.toExternalForm().contains(module.getName()))
					.collect(Collectors.toSet());
			// Clean up
			allHelpSets.removeAll(help);
			if (!help.isEmpty()) {
				results.put(module, help);
			}
		}
		return results;
	}

	class HelpThemeListener implements ThemeListener {
		@Override
		public void themeChanged(ThemeEvent event) {
			if (event.isLookAndFeelChanged()) {
				reload();
			}
		}
	}
}
