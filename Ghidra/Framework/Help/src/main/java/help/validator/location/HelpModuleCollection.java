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
package help.validator.location;

import java.io.File;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import javax.help.HelpSet;
import javax.help.Map.ID;
import javax.help.TOCView;
import javax.swing.tree.DefaultMutableTreeNode;

import docking.help.CustomTOCView.CustomTreeItemDecorator;
import help.HelpBuildUtils;
import help.TOCItemProvider;
import help.validator.model.*;

/**
 * A class that is meant to hold a single help <b>input</b> directory and 0 or more
 * <b>external, pre-built</b> help sources (i.e., jar file or directory).
 * <p>
 * <pre>
 * 						Note
 * 						Note
 * 						Note
 *
 *  This class is a bit conceptually muddled.  Our build system is reflected in this class in that
 *  we currently build one help module at a time.  Thus, any dependencies of that module being
 *  built can be passed into this "collection" at build time.   We used to build multiple help
 *  modules at once, resolving dependencies for all of the input modules after we built each
 *  module.  This class will need to be tweaked in order to go back to a build system with
 *  multiple input builds.
 *
 * </pre>
 */
public class HelpModuleCollection implements TOCItemProvider {

	private Collection<HelpModuleLocation> helpLocations;

	/** The help we are building */
	private HelpModuleLocation inputHelp;

	private List<HelpSet> externalHelpSets;
	private Map<PathKey, HelpFile> pathToHelpFileMap;

	/**
	 * Creates a help module collection that contains only a singe help module from a help
	 * directory, not a pre-built help jar.
	 * @param dir the directory containing help
	 * @return the help collection
	 */
	public static HelpModuleCollection fromHelpDirectory(File dir) {
		return new HelpModuleCollection(toHelpLocations(Collections.singleton(dir)));
	}

	/**
	 * Creates a help module collection that assumes zero or more pre-built help jar files and
	 * one help directory that is an input into the help building process.
	 * @param files the files from which to get help
	 * @return the help collection
	 */
	public static HelpModuleCollection fromFiles(Collection<File> files) {
		return new HelpModuleCollection(toHelpLocations(files));
	}

	/**
	 * Creates a help module collection that assumes zero or more pre-built help jar files and
	 * one help directory that is an input into the help building process.
	 * @param locations the locations from which to get help
	 * @return the help collection
	 */
	public static HelpModuleCollection fromHelpLocations(Collection<HelpModuleLocation> locations) {
		return new HelpModuleCollection(locations);
	}

	private static Set<HelpModuleLocation> toHelpLocations(Collection<File> files) {
		Set<HelpModuleLocation> set = new HashSet<>();
		for (File file : files) {
			set.add(HelpBuildUtils.toLocation(file));
		}
		return set;
	}

	private HelpModuleCollection(Collection<HelpModuleLocation> locations) {
		helpLocations = new LinkedHashSet<>(locations);

		loadTOCs();

		loadHelpSets();

		if (inputHelp == null && externalHelpSets.size() == 0) {
			throw new IllegalArgumentException(
				"Required TOC file does not exist.  " + "You must create a TOC_Source.xml file, " +
					"even if it is an empty template, or provide a pre-built TOC.  " +
					"Help directories: " + locations.toString());
		}
	}

	public GhidraTOCFile getSourceTOCFile() {
		return inputHelp.getSourceTOCFile();
	}

	private void loadTOCs() {

		for (HelpModuleLocation location : helpLocations) {
			if (!location.isHelpInputSource()) {
				continue;
			}

			if (inputHelp != null) {
				throw new IllegalArgumentException("Cannot have more than one source input " +
					"help module.  Found a second input module: " + location);
			}

			inputHelp = location;
		}
	}

	private void loadHelpSets() {

		externalHelpSets = new ArrayList<>();
		for (HelpModuleLocation location : helpLocations) {
			if (location.isHelpInputSource()) {
				continue; // help sets only exist in pre-built help 
			}

			HelpSet helpSet = location.getHelpSet();
			externalHelpSets.add(helpSet);
		}

		if (externalHelpSets.isEmpty()) {
			return;
		}
	}

	public boolean containsHelpFiles() {
		for (HelpModuleLocation location : helpLocations) {
			if (location.containsHelp()) {
				return true;
			}
		}
		return false;
	}

	public Collection<Path> getHelpRoots() {
		List<Path> result = new ArrayList<>();
		for (HelpModuleLocation location : helpLocations) {
			result.add(location.getHelpLocation());
		}
		return result;
	}

	public Map<HelpFile, Map<String, List<AnchorDefinition>>> getDuplicateAnchorsByFile() {

		Map<HelpFile, Map<String, List<AnchorDefinition>>> result = new HashMap<>();
		for (HelpModuleLocation location : helpLocations) {
			Map<HelpFile, Map<String, List<AnchorDefinition>>> anchors =
				location.getDuplicateAnchorsByFile();
			result.putAll(anchors);
		}
		return result;
	}

	public Map<HelpTopic, List<AnchorDefinition>> getDuplicateAnchorsByTopic() {
		Map<HelpTopic, List<AnchorDefinition>> result = new HashMap<>();
		for (HelpModuleLocation location : helpLocations) {
			Map<HelpTopic, List<AnchorDefinition>> anchors = location.getDuplicateAnchorsByTopic();
			result.putAll(anchors);
		}
		return result;
	}

	public Collection<HREF> getAllHREFs() {

		List<HREF> result = new ArrayList<>();
		for (HelpModuleLocation location : helpLocations) {
			result.addAll(location.getAllHREFs());
		}
		return result;
	}

	public Collection<IMG> getAllIMGs() {
		List<IMG> result = new ArrayList<>();
		for (HelpModuleLocation location : helpLocations) {
			result.addAll(location.getAllIMGs());
		}
		return result;
	}

	public Collection<AnchorDefinition> getAllAnchorDefinitions() {
		List<AnchorDefinition> result = new ArrayList<>();
		for (HelpModuleLocation location : helpLocations) {
			result.addAll(location.getAllAnchorDefinitions());
		}
		return result;
	}

	public AnchorDefinition getAnchorDefinition(Path target) {
		Map<PathKey, HelpFile> map = getPathHelpFileMap();
		HelpFile helpFile = map.get(new PathKey(target));
		if (helpFile == null) {
			return null;
		}

		AnchorDefinition definition = helpFile.getAnchorDefinition(target);
		return definition;
	}

	public HelpFile getHelpFile(Path helpPath) {
		if (helpPath == null) {
			return null;
		}

		Map<PathKey, HelpFile> map = getPathHelpFileMap();
		return map.get(new PathKey(helpPath));
	}

	private Map<PathKey, HelpFile> getPathHelpFileMap() {
		if (pathToHelpFileMap == null) {
			pathToHelpFileMap = new HashMap<>();
			for (HelpModuleLocation location : helpLocations) {
				Collection<HelpFile> helpFiles = location.getHelpFiles();
				for (HelpFile helpFile : helpFiles) {
					PathKey entry = new PathKey(helpFile.getRelativePath());
					pathToHelpFileMap.put(entry, helpFile);
				}
			}
		}
		return pathToHelpFileMap;
	}

	@Override
	public Map<String, TOCItemDefinition> getTocDefinitionsByID() {
		Map<String, TOCItemDefinition> map = new HashMap<>();
		GhidraTOCFile TOC = inputHelp.getSourceTOCFile();
		map.putAll(TOC.getTOCDefinitionByIDMapping());
		return map;
	}

	@Override
	public Map<String, TOCItemExternal> getExternalTocItemsById() {
		Map<String, TOCItemExternal> map = new HashMap<>();

		if (externalHelpSets.isEmpty()) {
			return map;
		}

		for (HelpSet helpSet : externalHelpSets) {
			TOCView view = (TOCView) helpSet.getNavigatorView("TOC");
			DefaultMutableTreeNode node = view.getDataAsTree();
			URL url = helpSet.getHelpSetURL();
			try {
				URL dataURL = new URL(url, (String) view.getParameters().get("data"));
				Path path = Paths.get(dataURL.toURI());
				addPrebuiltItem(node, path, map);
			}
			catch (MalformedURLException | URISyntaxException e) {
				throw new RuntimeException("Internal error", e);
			}
		}
		return map;
	}

	private void addPrebuiltItem(DefaultMutableTreeNode tn, Path tocPath,
			Map<String, TOCItemExternal> mapByDisplay) {

		Object userObject = tn.getUserObject();
		CustomTreeItemDecorator item = (CustomTreeItemDecorator) userObject;
		if (item != null) {
			DefaultMutableTreeNode parent = (DefaultMutableTreeNode) tn.getParent();
			TOCItemExternal parentItem = null;
			if (parent != null) {
				CustomTreeItemDecorator dec = (CustomTreeItemDecorator) parent.getUserObject();
				if (dec != null) {
					parentItem = mapByDisplay.get(dec.getTocID());
				}
			}

			ID targetID = item.getID();
			String displayText = item.getDisplayText();
			String tocId = item.getTocID();
			String target = targetID == null ? null : targetID.getIDString();
			TOCItemExternal external = new TOCItemExternal(parentItem, tocPath, tocId, displayText,
				target, item.getName(), -1);
			mapByDisplay.put(tocId, external);
		}

		@SuppressWarnings("rawtypes")
		Enumeration children = tn.children();
		while (children.hasMoreElements()) {
			DefaultMutableTreeNode child = (DefaultMutableTreeNode) children.nextElement();
			addPrebuiltItem(child, tocPath, mapByDisplay);
		}
	}

	/**
	 * Input TOC items are those that we are building for the input help module of this collection
	 * @return the items
	 */
	public Collection<TOCItem> getInputTOCItems() {
		Collection<TOCItem> items = new ArrayList<>();
		GhidraTOCFile TOC = inputHelp.getSourceTOCFile();
		items.addAll(TOC.getAllTOCItems());
		return items;
	}

	public Collection<HREF> getTOC_HREFs() {
		Collection<HREF> definitions = new ArrayList<>();
		GhidraTOCFile TOC = inputHelp.getSourceTOCFile();
		definitions.addAll(getTOC_HREFs(TOC));
		return definitions;
	}

	private Collection<HREF> getTOC_HREFs(GhidraTOCFile file) {
		Collection<TOCItemDefinition> definitions = file.getTOCDefinitions();
		Collection<HREF> hrefs = new HashSet<>();
		for (TOCItemDefinition definition : definitions) {
			if (definition.getTargetAttribute() == null) {
				continue;
			}
			try {
				hrefs.add(new HREF(inputHelp, file.getFile(), definition.getTargetAttribute(),
					definition.getLineNumber()));
			}
			catch (URISyntaxException e) {
				throw new RuntimeException("Malformed reference: ", e);
			}
		}
		return hrefs;
	}

	@Override
	public String toString() {
		return helpLocations.toString();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/** A class that wraps a Path and allows map lookup for paths from different file systems */
	private class PathKey {
		private String path;

		PathKey(Path p) {
			if (p == null) {
				throw new IllegalArgumentException("Path cannot be null");
			}
			this.path = p.toString().replace('\\', '/');
		}

		@Override
		public int hashCode() {
			return path.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}

			PathKey other = (PathKey) obj;

			boolean result = path.equals(other.path);
			return result;
		}

		@Override
		public String toString() {
			return path.toString();
		}
	}
}
