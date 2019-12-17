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

import java.awt.Component;
import java.net.URL;

import ghidra.util.HelpLocation;

/**
 * <code>HelpService</code> defines a service for displaying Help content by
 * an ID or URL.
 */
public interface HelpService {

	public static final String DUMMY_HELP_SET_NAME = "Dummy_HelpSet.hs";

	/**
	 * Display the Help content identified by the help object.
	 * 
	 * @param helpObject the object to which help was previously registered
	 * @param infoOnly display {@link HelpLocation} information only, not the help UI
	 * @param parent requesting component
	 * 
	 * @see #registerHelp(Object, HelpLocation)
	 */
	public void showHelp(Object helpObject, boolean infoOnly, Component parent);

	/**
	 * Display the help page for the given URL.  This is a specialty method for displaying
	 * help when a specific file is desired, like an introduction page.  Showing help for 
	 * objects within the system is accomplished by calling 
	 * {@link #showHelp(Object, boolean, Component)}.
	 * 
	 * @param url the URL to display
	 * @see #showHelp(Object, boolean, Component)
	 */
	public void showHelp(URL url);

	/**
	 * Signals to the help system to ignore the given object when searching for and validating 
	 * help.  Once this method has been called, no help can be registered for the given object.
	 * 
	 * @param helpObject the object to exclude from the help system.
	 */
	public void excludeFromHelp(Object helpObject);

	/**
	 * Returns true if the given object is meant to be ignored by the help system
	 * 
	 * @param helpObject the object to check
	 * @return true if ignored
	 * @see #excludeFromHelp(Object)
	 */
	public boolean isExcludedFromHelp(Object helpObject);

	/**
	 * Register help for a specific object.  
	 * 
	 * <P>Do not call this method will a <code>null</code> help location.  Instead, to signal that
	 * an item has no help, call {@link #excludeFromHelp(Object)}.
	 * 
	 * @param helpObject the object to associate the specified help location with
	 * @param helpLocation help content location
	 */
	public void registerHelp(Object helpObject, HelpLocation helpLocation);

	/**
	 * Removes this object from the help system.  This method is useful, for example, 
	 * when a single Java {@link Component} will have different help locations 
	 * assigned over its lifecycle.
	 * 
	 * @param helpObject the object for which to clear help
	 */
	public void clearHelp(Object helpObject);

	/**
	 * Returns the registered (via {@link #registerHelp(Object, HelpLocation)} help 
	 * location for the given object; null if there is no registered
	 * help.
	 * 
	 * @param object The object for which to find a registered HelpLocation.
	 * @return the registered HelpLocation
	 * @see #registerHelp(Object, HelpLocation)
	 */
	public HelpLocation getHelpLocation(Object object);

	/**
	 * Returns true if the help system has been initialized properly; false if help does not
	 * exist or is not working.
	 * 
	 * @return true if the help system has found the applications help content and has finished
	 *         initializing
	 */
	public boolean helpExists();
}
