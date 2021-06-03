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
package docking.help;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;
import java.util.Map.Entry;
import java.util.Set;

import javax.help.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.SystemUtilities;

/**
 * Ghidra help set that creates a GhidraHelpBroker, installs some custom HTML handling code via
 * the GHelpHTMLEditorKit, and most importantly, changes how the JavaHelp system works with 
 * regard to integrating Help Sets.
 * <p>
 * The HelpSet class uses a javax.help.Map object to locate HTML files by javax.help.map.ID objects.
 * This class has overridden that basic usage of the Map object to allow ID lookups to take 
 * place across GHelpSet objects.  We need to do this due to how we merge help set content 
 * across modules.  More specifically, in order to merge, we have to make all {@code <tocitem>} xml tags
 * the same, including the target HTML file they may reference.  Well, when a module uses a 
 * {@code <tocitem>} tag that references an HTML file <b>not inside of it's module</b>, then JavaHelp 
 * considers this an error and does not correctly merge the HelpSets that share the reference.
 * Further, it does not properly locate the shared HTML file reference.  This class allows lookups
 * across modules by overridden the lookup functionality done by the map object.  More specifically,
 * we override {@link #getCombinedMap()} and {@link #getLocalMap()} to use a custom delegate map
 * object that knows how do do this "cross-module" help lookup.
 * 
 *
 *@see GHelpHTMLEditorKit
 */
public class GHelpSet extends HelpSet {

	private static final String HOME_ID = "Misc_Welcome_to_Ghidra_Help";

	/** <b>static</b> map that contains all known help sets in the system. */
	private static java.util.Map<HelpSet, Map> helpSetsToCombinedMaps = new java.util.HashMap<>();
	private static java.util.Map<HelpSet, Map> helpSetsToLocalMaps = new java.util.HashMap<>();

	private Logger LOG = LogManager.getLogger(GHelpSet.class);

	private GHelpMap combinedMapWrapper;
	private GHelpMap localMapWrapper;

	public GHelpSet(ClassLoader loader, URL helpset) throws HelpSetException {
		super(loader, helpset);
		init();
	}

	private void init() {

		// swap in Ghidra's editor kit, which is an overridden version of Java's
		String type = "text/html";
		String editorKit = GHelpHTMLEditorKit.class.getName();
		ClassLoader classLoader = getClass().getClassLoader();
		setKeyData(kitTypeRegistry, type, editorKit);
		setKeyData(kitLoaderRegistry, type, classLoader);

		setHomeID(HOME_ID);

		initializeCombinedMapWrapper();
	}

	@Override
	public HelpBroker createHelpBroker() {
		return new GHelpBroker(this);
	}

	@Override
	public Map getLocalMap() {
		Map localMap = super.getLocalMap();
		if (localMap == null) {
			return null;
		}

		initializeLocalMapWrapper();
		return localMapWrapper;
	}

	private void initializeLocalMapWrapper() {
		if (localMapWrapper == null) {
			Map localMap = super.getLocalMap();
			helpSetsToLocalMaps.put(this, localMap);
			localMapWrapper = new GHelpMap(localMap);
		}
	}

	@Override
	public Map getCombinedMap() {
		return combinedMapWrapper;
	}

	private void initializeCombinedMapWrapper() {
		if (combinedMapWrapper == null) {
			Map combinedMap = super.getCombinedMap();
			helpSetsToCombinedMaps.put(this, combinedMap);
			combinedMapWrapper = new GHelpMap(combinedMap);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	/** A special class to allow us to handle help ID lookups across help sets */
	private class GHelpMap implements Map {
		private final Map mapDelegate;

		private GHelpMap(Map mapDelegate) {
			this.mapDelegate = mapDelegate;
		}

		@Override
		public Enumeration<?> getAllIDs() {
			return mapDelegate.getAllIDs();
		}

		@Override
		public ID getClosestID(URL url) {
			ID closestID = mapDelegate.getClosestID(url);
			if (closestID != null) {
				return closestID; // it's in our map
			}

			LOG.trace("Help Set \"" + GHelpSet.this + "\" does not contain ID for URL: " + url);

			Set<Entry<HelpSet, Map>> entrySet = helpSetsToCombinedMaps.entrySet();
			for (Entry<HelpSet, Map> entry : entrySet) {
				Map map = entry.getValue();
				closestID = map.getClosestID(url);
				if (closestID != null) {
					return closestID;
				}
			}

			LOG.trace("No ID found in any HelpSet for URL: " + url);

			return null;
		}

		@Override
		public ID getIDFromURL(URL url) {
			return mapDelegate.getIDFromURL(url);
		}

		@Override
		public Enumeration<?> getIDs(URL url) {
			return mapDelegate.getIDs(url);
		}

		@Override
		public URL getURLFromID(ID id) throws MalformedURLException {
			URL URL = mapDelegate.getURLFromID(id);
			if (URL != null) {
				return URL; // it's in our map
			}

			Set<Entry<HelpSet, Map>> entrySet = helpSetsToCombinedMaps.entrySet();
			for (Entry<HelpSet, Map> entry : entrySet) {
				Map map = entry.getValue();
				URL = map.getURLFromID(id);
				if (URL != null) {
					return URL;
				}
			}

			LOG.trace("No URL found in any HelpSet for ID: " + id);

			URL = tryToCreateURLFromID(id.id);
			if (URL != null) {
				return URL;
			}

			return null;
		}

		/**
		 * This is meant for help files that are not included in the standard help system.  Their
		 * id paths are expected to be relative to the application install directory.
		 * @param id the help id.
		 * @return the URL to the help file.
		 */
		private URL tryToCreateURLFromID(String id) {

			URL fileURL = createFileURL(id);
			if (fileURL != null) {
				return fileURL;
			}

			URL rawURL = createRawURL(id);
			return rawURL;
		}

		private URL createRawURL(String id) {

			URL url = null;
			try {
				url = new URL(id);
			}
			catch (MalformedURLException e) {
				LOG.trace("ID is not a URL; tried to make URL from string: " + id);
				return null;
			}

			try {
				InputStream inputStream = url.openStream();
				inputStream.close();
				return url; // it is valid
			}
			catch (IOException e) {
				LOG.trace("ID is not a URL; unable to read URL: " + url);
			}

			return null;
		}

		private URL createFileURL(String id) {
			ResourceFile helpFile = fileFromID(id);
			if (!helpFile.exists()) {
				LOG.trace("ID is not a file; tried: " + helpFile);
				return null;
			}

			try {
				return helpFile.toURL();
			}
			catch (MalformedURLException e) {
				// this shouldn't happen, as the file exists
				LOG.trace("ID is not a URL; tried to make URL from file: " + helpFile);
			}
			return null;
		}

		private ResourceFile fileFromID(String id) {
			// this allows us to find files by using relative paths (e.g., 'docs/WhatsNew.html'
			// will get resolved relative to the installation directory in a build).
			ResourceFile installDir = Application.getInstallationDirectory();
			ResourceFile helpFile = new ResourceFile(installDir, id);
			return helpFile;
		}

		@Override
		public boolean isID(URL url) {
			return mapDelegate.isID(url);
		}

		@Override
		public boolean isValidID(String id, HelpSet hs) {

			HelpService service = Help.getHelpService();
			if (!service.helpExists()) {
				// Treat everything as valid until all help is loaded, otherwise, we 
				// can't be sure that when something is missing, it is just not yet merged in.
				return true;
			}

			boolean isValid = mapDelegate.isValidID(id, hs);
			if (isValid) {
				return true;
			}

			Set<Entry<HelpSet, Map>> entrySet = helpSetsToCombinedMaps.entrySet();
			for (Entry<HelpSet, Map> entry : entrySet) {
				Map map = entry.getValue();
				if (map.isValidID(id, hs)) {
					return true;
				}
			}

			// This can happen for help files that are generated during the build, 
			// such as 'What's New'; return true here so the values will still be loaded into
			// the help system; handle the error condition later.
			if (ignoreExternalHelp(id)) {
				return true;
			}

			return false;
		}

		private boolean ignoreExternalHelp(String id) {
			if (id.startsWith("help/topics")) {
				return false; // not external help location
			}

			URL url = tryToCreateURLFromID(id);
			if (url != null) {
				return true; // ignore this id; it is valid
			}

			// no url for ID
			if (SystemUtilities.isInDevelopmentMode()) {
				// ignore external files that do not exist in dev mode
				return true;
			}

			return false;
		}
	}
}
