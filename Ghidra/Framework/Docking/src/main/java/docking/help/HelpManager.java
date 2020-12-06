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

import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.help.*;
import javax.help.Map.ID;
import javax.swing.JButton;
import javax.swing.UIManager;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import generic.util.WindowUtilities;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;
import utilities.util.reflection.ReflectionUtilities;

/**
 * Class that uses JavaHelp browser to show context sensitive help.
 * 
 * <p>Note: this manager will validate all registered help when in development mode.  In order
 * to catch items that have not registered help at all, we rely on those items to register a 
 * default {@link HelpLocation} that will get flagged as invalid.  Examples of this usage are
 * the {@link DockingActionIf} and the {@link ComponentProvider} base classes.
 */
public class HelpManager implements HelpService {

	public static final String SHOW_AID_KEY = "SHOW.HELP.NAVIGATION.AID";
	private static final String TABLE_OF_CONTENTS_FILENAME_KEY = "data";

	private final static URL HELP_NOT_FOUND_PAGE_URL =
		ResourceManager.getResource("help/empty.htm");

	private static final String TABLE_OF_CONTENTS_VIEW_NAME = "TOC";

	private static final String GHIDRA_HELP_TITLE = "Ghidra Help";

	private GHelpSet mainHS;
	private HelpBroker mainHB;

	private HashMap<URL, HelpSet> urlToHelpSets = new HashMap<>();
	private Map<Object, HelpLocation> helpLocations = new WeakHashMap<>();

	private List<HelpSet> helpSetsPendingMerge = new ArrayList<>();
	private boolean hasMergedHelpSets;

	/** If the help is not built, then this will be false */
	private boolean isValidHelp;
	private boolean hasBeenDisplayed;

	private Set<Object> excludedFromHelp = Collections.newSetFromMap(new WeakHashMap<>());

	/**
	 * Constructor.
	 * 
	 * @param url url for the main HelpSet file for the application.
	 * @throws HelpSetException if HelpSet could not be created
	 */
	protected HelpManager(URL url) throws HelpSetException {
		mainHS = new GHelpSet(new GHelpClassLoader(null), url);
		mainHB = mainHS.createHelpBroker();
		mainHS.setTitle(GHIDRA_HELP_TITLE);

		setColorResources();

		isValidHelp = isValidHelp();
	}

	protected void registerHelp() {
		mergePendingHelpSets();
		Help.installHelpService(this);
	}

	@Override
	public boolean helpExists() {
		return isValidHelp && hasMergedHelpSets;
	}

	/**
	 * Add the help set for the given URL.
	 * 
	 * @param url url for the HelpSet (.hs) file
	 * @param classLoader the help classloader that knows how to find help modules in the classpath
	 * @throws HelpSetException if the help set could not be created from the given URL.
	 */
	public void addHelpSet(URL url, GHelpClassLoader classLoader) throws HelpSetException {
		HelpSet hs = createHelpSet(url, classLoader);
		if (hs == null) {
			return;
		}

		if (hasMergedHelpSets) {
			mainHS.add(hs);
		}
		else {
			helpSetsPendingMerge.add(hs);
		}
	}

	@Override
	public void excludeFromHelp(Object helpObject) {
		excludedFromHelp.add(helpObject);
		helpLocations.remove(helpObject);
	}

	@Override
	public boolean isExcludedFromHelp(Object helpObject) {
		return excludedFromHelp.contains(helpObject);
	}

	@Override
	public void clearHelp(Object helpObject) {
		helpLocations.remove(helpObject);
	}

	@Override
	public void registerHelp(Object helpObject, HelpLocation location) {

		if (location == null) {
			Throwable t = ReflectionUtilities.createJavaFilteredThrowable();
			Msg.debug(this, "Deprecated use of registerHelp() - use excludeFromHelp()\n", t);
			excludeFromHelp(helpObject);
			return;
		}

		if (helpObject instanceof Window) {
			// we do not allow this, as it causes unintended behavior when searching for help
			Msg.error(this, "Cannot register help for a top-level window", new AssertException());
			return;
		}

		if (isExcluded(helpObject)) {
			return;
		}

		// Implementation Note: the same object can have different help registered.  For example,
		//                      DockingActions do this as part of their construction process. 
		//                      These actions will register a default help location and then 
		//                      subclasses may change that location.  We always use the most
		//                      recently registered action.
		helpLocations.put(helpObject, location);
	}

	private boolean isExcluded(Object helpee) {
		if (excludedFromHelp.contains(helpee)) {
			return true;
		}

		return false;
	}

	/**
	 * Returns the Help location associated with the specified object
	 * or null if no help has been registered for the object.
	 * @param helpObj help object
	 * @return help location
	 */
	@Override
	public HelpLocation getHelpLocation(Object helpObj) {
		return helpLocations.get(helpObj);
	}

	/**
	 * Returns the master help set (the one into which all other help sets are merged).
	 */
	public GHelpSet getMasterHelpSet() {
		return mainHS;
	}

	/**
	 * Display the help page for the given URL.  This is a specialty method for displaying
	 * help when a specific file is desired, like an introduction page.  Showing help for 
	 * objects within the system is accomplished by calling 
	 * {@link #showHelp(Object, boolean, Component)}.
	 * 
	 * @param url the URL to display
	 * @see #showHelp(Object, boolean, Component)
	 */
	@Override
	public void showHelp(URL url) {
		if (!isValidHelp) {
			Msg.warn(this, "Help is not in a valid state.  " +
				"This can happen when help has not been built.");
			return;
		}

		KeyboardFocusManager keyboardFocusManager =
			KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Window window = keyboardFocusManager.getActiveWindow();
		displayHelp(url, window);
	}

	@Override
	public void showHelp(Object helpObj, boolean infoOnly, Component owner) {

		if (!isValidHelp && !infoOnly) {
			Msg.warn(this, "Help is not in a valid state.  " +
				"This can happen when help has not been built.");
			return;
		}

		while (owner != null && !(owner instanceof Window)) {
			owner = owner.getParent();
		}

		Window window = (Window) owner;
		Dialog modalDialog = WindowUtilities.findModalestDialog();
		if (modalDialog != null) {
			window = modalDialog;
		}

		HelpLocation loc = findHelpLocation(helpObj);

		if (infoOnly) {
			displayHelpInfo(helpObj, loc, window);
			return;
		}

		if (loc != null) {

			URL url = loc.getHelpURL();
			if (url != null) {
				displayHelp(url, window);
				return;
			}

			String helpIDString = loc.getHelpId();
			if (helpIDString != null) {
				try {
					displayHelp(createHelpID(helpIDString), window);
					return;
				}
				catch (BadIDException e) {
					Msg.info(this, "Could not find help for ID: \"" + helpIDString +
						"\" from HelpLocation: " + loc);
				}
			}
		}
		displayHelp(mainHS.getHomeID(), window);
	}

	private ID createHelpID(String helpIDString) {
		BadIDException helpException = null;

		try {
			return ID.create(helpIDString, mainHS);
		}
		catch (BadIDException bide) {
			helpException = bide; // save in case we need later
		}

		// We get here on an exception; let's try to our alternative help lookup.
		// To do this, try making a URL out of the help string and doing a reverse lookup
		URL URL = null;
		try {
			URL = new URL(helpIDString);
		}
		catch (MalformedURLException e) {
			// nothing we can do, fall through the method to the previous exception
		}

		if (URL != null) {
			javax.help.Map combinedMap = mainHS.getCombinedMap();
			ID ID = combinedMap.getIDFromURL(URL);
			if (ID != null) {
				return ID;
			}
		}

		throw helpException;
	}

	private HelpLocation findHelpLocation(Object helpObj) {
		if (helpObj instanceof HelpDescriptor) {
			HelpDescriptor helpDescriptor = (HelpDescriptor) helpObj;
			Object helpObject = helpDescriptor.getHelpObject();
			return helpLocations.get(helpObject);
		}
		return helpLocations.get(helpObj);
	}

	private String getFilenameForHelpLocation(HelpLocation helpLocation) {
		URL helpFileURL = getURLForHelpLocation(helpLocation);
		if (helpFileURL == null) {
			return null;
		}

		String file = helpFileURL.getFile();
		int filenameStart = file.lastIndexOf('/') + 1; // filename start within full path string
		int anchorIndex = file.indexOf('#'); // help topic anchor
		int filenameEnd = (anchorIndex == -1) ? file.length() : anchorIndex;
		return file.substring(filenameStart, filenameEnd);
	}

	private URL getURLForHelpLocation(HelpLocation helpLocation) {
		String helpId = helpLocation.getHelpId();
		ID id = null;
		try {
			id = createHelpID(helpId);
		}
		catch (BadIDException e) {
			return null;
		}

		// this can happen when the HelpLocation has a null helpId value
		if (id == null) {
			return helpLocation.getHelpURL();
		}

		HelpSet hs = id.hs;
		try {
			return hs.getCombinedMap().getURLFromID(id);
		}
		catch (MalformedURLException e) {
			// we return null
		}
		return null;
	}

	private boolean hasValidHelp(Object helpee, HelpLocation location) {
		if (isKeybindingOnly(helpee)) {
			// no help for keybindings, as they do not have GUI widgets
			return true;
		}

		if (location == null) {
			return false;
		}

		return isValidHelpLocation(location);
	}

	private boolean isValidHelpLocation(HelpLocation helpLoc) {
		if (helpLoc.getHelpURL() != null) {
			return true; // URL always assumed to be good
		}

		String helpId = helpLoc.getHelpId();
		ID id = null;
		try {
			id = createHelpID(helpId);
		}
		catch (BadIDException e) {
			// just return false
		}
		if (id == null) {
			return false;
		}

		HelpSet helpSet = id.getHelpSet();
		javax.help.Map combinedMap = helpSet.getCombinedMap();
		try {
			URL url = combinedMap.getURLFromID(id);
			if (url == null) {
				// not sure when this can happen, log it for now
				Msg.debug(this, "Unable to find help for ID: " + id);
				return false;
			}

			return isURLValid(url);
		}
		catch (MalformedURLException e) {
			return false;
		}
	}

	private void displayHelp(final Object help, final Window owner) {
		if (help == null) {
			return;
		}

		boolean wasDisplayed = mainHB.isDisplayed();
		if (mainHB instanceof DefaultHelpBroker) {
			((DefaultHelpBroker) mainHB).setActivationWindow(owner);
		}

		// make sure we are visible before we set data (prevents bugs in JavaHelp)		
		mainHB.setDisplayed(true);

		if (!wasDisplayed) {
			//
			// Unusual Code Alert!: The initial load of the UI will use a SwingWorker to reload
			//                      the help model.  If it finishes after we set our desired
			// 				        help value, then the TOC item is not properly selected.  Using
			//		                an invokeLater() will work as long as the model loading is
			//                      relatively quick.
			//
			SystemUtilities.runSwingLater(() -> displayHelp(help, owner));
			return;
		}

		mergePendingHelpSets();

		URL helpURL = null;
		if (help instanceof ID) {
			helpURL = getURLForID((ID) help);
		}
		else if (help instanceof URL) {
			helpURL = (URL) help;
		}

		displayHelpUrl(help, helpURL);

		printBadHelp();

		hasBeenDisplayed = true;
	}

	private void printBadHelp() {

		if (!SystemUtilities.isInDevelopmentMode()) {
			return;
		}

		if (hasBeenDisplayed) {
			// only show this once
			return;
		}

		TaskLauncher.launchNonModal("Validating Help", monitor -> {
			try {
				printBadHelp(monitor);
			}
			catch (CancelledException e) {
				// user cancelled; just exit
			}
		});
	}

	private void printBadHelp(TaskMonitor monitor) throws CancelledException {

		Map<Object, HelpLocation> badHelp = getInvalidHelpLocations(monitor);
		if (badHelp.isEmpty()) {
			return;
		}

		StringBuilder buffy = new StringBuilder();
		buffy.append("Found the following invalid help locations:\n");
		for (HelpLocation loc : badHelp.values()) {
			buffy.append('\t').append(loc.toString()).append('\n');
			buffy.append("                ").append(loc.getInceptionInformation()).append('\n');
		}

		new Throwable("Bad Help Locations Found!\n" + buffy.toString()).printStackTrace();
	}

	public Map<Object, HelpLocation> getInvalidHelpLocations(TaskMonitor monitor)
			throws CancelledException {

		Map<Object, HelpLocation> map = new WeakHashMap<>();

		Map<Object, HelpLocation> helpLocationsCopy = copyHelpLocations();
		monitor.initialize(helpLocationsCopy.size());
		Set<Entry<Object, HelpLocation>> entries = helpLocationsCopy.entrySet();
		for (Entry<Object, HelpLocation> entry : entries) {
			monitor.checkCanceled();

			Object helpee = entry.getKey();
			HelpLocation location = entry.getValue();
			monitor.setMessage("Checking " + helpee);
			if (!hasValidHelp(helpee, location)) {
				map.put(helpee, location);
			}
			monitor.incrementProgress(1);
		}
		return map;
	}

	private Map<Object, HelpLocation> copyHelpLocations() {
		// we must copy the help locations, since we are in a background thread and the 
		// locations map is frequently updated by the Swing thread
		return Swing.runNow(() -> new HashMap<>(helpLocations));
	}

	//
	// 				Warning!
	// This code has timing implications.  DockingActions register themselves with the help
	// system as part of their construction.  At that point, they are not usually fully 
	// constructed, as most clients will use the newly constructed action to set the various
	// toolbar/menu/popup data elements.  For us to know if the action is really only for 
	// keybinding purposes, we have to do this check after the action is fully constructed.
	//
	private boolean isKeybindingOnly(Object helpee) {
		if (!(helpee instanceof DockingActionIf)) {
			return false;
		}

		DockingActionIf action = (DockingActionIf) helpee;
		if (action.getToolBarData() != null) {
			return false;
		}
		if (action.getMenuBarData() != null) {
			return false;
		}
		if (action.getPopupMenuData() != null) {
			return false;
		}
		return true;
	}

	private void displayHelpUrl(Object help, URL helpUrl) {
		if (helpUrl == null) {
			Msg.debug(this, "Unable to find help for object: " + help);
		}

		helpUrl = validateUrl(helpUrl);

		if (hasBeenDisplayed && helpUrl.equals(mainHB.getCurrentURL())) {
			reloadPage(helpUrl);
			return;
		}

		mainHB.setCurrentURL(validateUrl(helpUrl));
	}

	/** This forces page to be redisplayed when location has not changed */
	private void reloadPage(URL helpURL) {

		if (!(mainHB instanceof GHelpBroker)) {
			// not our broker installed; can't force a reload
			return;
		}

		((GHelpBroker) mainHB).reloadHelpPage(validateUrl(helpURL));
	}

	private URL getURLForID(ID ID) {
		javax.help.Map map = mainHS.getCombinedMap();
		try {
			return map.getURLFromID(ID);
		}
		catch (MalformedURLException e) {
			return null;
		}
	}

	private URL validateUrl(URL url) {
		if (url == null) {
			return HELP_NOT_FOUND_PAGE_URL;
		}

		try {
			InputStream inputStream = url.openStream();
			inputStream.close();
			return url;
		}
		catch (IOException e) {
			// handled below
		}

		return HELP_NOT_FOUND_PAGE_URL;
	}

	/** Make sure we can find the help resources that Ghidra will use */
	private boolean isValidHelp() {
		NavigatorView TOCView = mainHS.getNavigatorView(TABLE_OF_CONTENTS_VIEW_NAME);
		Hashtable<?, ?> parametersTable = TOCView.getParameters();
		String filename = (String) parametersTable.get(TABLE_OF_CONTENTS_FILENAME_KEY);
		ClassLoader loader = mainHS.getLoader();
		URL testResource = loader.getResource(filename);
		if (testResource == null) {
			return false;
		}
		return isURLValid(testResource);
	}

	private boolean isURLValid(URL url) {
		InputStream testStream = null;
		try {
			testStream = url.openStream();
			return true; // if the above didn't fail, then the resource can be accessed
		}
		catch (MalformedURLException e) {
			return false; // shouldn't happen as the URL should be valid
		}
		catch (IOException e) {
			return false; // this happens if the resource doesn't exit
		}
		finally {
			if (testStream != null) {
				try {
					testStream.close();
				}
				catch (IOException e) {
					// don't care, we tried to close it
				}
			}
		}
	}

	protected void mergePendingHelpSets() {
		for (HelpSet helpSet : helpSetsPendingMerge) {
			try {
				if (isExcludedHelpSet(helpSet)) {
					continue;
				}

				mainHS.add(helpSet);
			}
			catch (Exception e) {
				Msg.warn(this,
					"Unable to load HelpSet: " + helpSet.getHelpSetURL().toExternalForm(), e);
			}
		}

		// Note: not sure if we ever need to merge again after the initial load.  If so, then
		//       this flag doesn't make sense.  However, as of this writing, we do not discover 
		//       new help sets on the fly.
		hasMergedHelpSets = true;
		helpSetsPendingMerge.clear();
	}

	boolean hasMergedHelpSets() {
		return hasMergedHelpSets;
	}

	private boolean isExcludedHelpSet(HelpSet helpSet) {
		if (mainHS.getHelpSetURL().equals(helpSet.getHelpSetURL())) {
			return true; // don't add the main help set to itself
		}

		URL URL = helpSet.getHelpSetURL();
		String URLString = URL.toString();
		if (URLString.endsWith(DUMMY_HELP_SET_NAME)) {
			return true;
		}

		return false;
	}

	/**
	 * Create a new help set for the given url, if one does
	 * not already exist.
	 * @param classLoader 
	 */
	private HelpSet createHelpSet(URL url, GHelpClassLoader classLoader) throws HelpSetException {
		if (!urlToHelpSets.containsKey(url)) {
			GHelpSet hs = new GHelpSet(classLoader, url);
			urlToHelpSets.put(url, hs);
			return hs;
		}
		return null;
	}

	/** 
	 * Set the color resources on the JEditorPane for selection so that
	 * you can see the highlights when you do a search in the JavaHelp.
	 */
	private void setColorResources() {
		UIManager.put("EditorPane.selectionBackground", new Color(204, 204, 255));
		UIManager.put("EditorPane.selectionForeground", UIManager.get("EditorPane.foreground"));
	}

	private void displayHelpInfo(Object helpObj, HelpLocation loc, Window parent) {
		String msg = getHelpInfo(helpObj, loc);
		Msg.showInfo(this, parent, "Help Info", msg);
	}

	private String getHelpInfo(Object helpObj, HelpLocation helpLoc) {
		if (helpObj == null) {
			return "Help Object is null";
		}

		boolean isHelpDescriptor = false;
		StringBuilder buffy = new StringBuilder();
		buffy.append("HELP OBJECT: " + helpObj.getClass().getName());
		buffy.append("\n");
		if (helpObj instanceof HelpDescriptor) {
			HelpDescriptor helpDescriptor = (HelpDescriptor) helpObj;
			buffy.append(helpDescriptor.getHelpInfo());
			isHelpDescriptor = true;
		}
		else if (helpObj instanceof JButton) {
			JButton button = (JButton) helpObj;
			buffy.append("   BUTTON: " + button.getText());
			buffy.append("\n");
			Component c = button;
			while (c != null && !(c instanceof Window)) {
				c = c.getParent();
			}
			if (c instanceof Dialog) {
				buffy.append("   DIALOG: " + ((Dialog) c).getTitle());
				buffy.append("\n");
			}
			if (c instanceof Frame) {
				buffy.append("   FRAME: " + ((Frame) c).getTitle());
				buffy.append("\n");
			}
		}
		buffy.append("\nHELP-LOCATION-> ");
		if (helpLoc != null) {
			buffy.append(helpLoc.toString());
			String str = helpLoc.getTopic();
			if (str != null) {
				buffy.append("\n   TOPIC:       ");
				buffy.append(str);
			}

			String filename = getFilenameForHelpLocation(helpLoc);
			if (filename != null) { // should never be null
				buffy.append("\n   FILENAME: ");
				buffy.append(filename);
			}

			str = helpLoc.getAnchor();
			if (str != null) {
				buffy.append("\n   ANCHOR:   ");
				buffy.append(str);
			}

			if (!isHelpDescriptor) { // don't put the info in twice
				String inception = helpLoc.getInceptionInformation();
				if (inception != null) {
					buffy.append("\n   \n");
					buffy.append("   CREATED AT: " + inception);
					buffy.append("\n   ");
				}
			}
		}
		else {
			buffy.append("<NO HELP AVAILABLE>");
		}

		return buffy.toString();
	}
}
