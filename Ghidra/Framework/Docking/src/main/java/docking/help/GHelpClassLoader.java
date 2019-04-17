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

import java.net.MalformedURLException;
import java.net.URL;

import generic.jar.ResourceFile;
import ghidra.util.Msg;
import resources.ResourceManager;

/**
 * A {@link ClassLoader} for loading help data.  This is only need when running in Eclipse.  We
 * do not include help data in the source tree for any module, in order to save build time.  By
 * doing this, we need a way to allow the Java Help system to find this data.  We have
 * Overridden {@link #findResource(String)} to look in our module directories for their
 * respective help.
 * <p>
 * This class is not needed in an installation since the help is bundled into jar files that
 * live in the classpath and thus the default class loader will find them.
 */
public class GHelpClassLoader extends ClassLoader {

	private final ResourceFile moduleDirectory;

	/**
	 * Constructs this class loader with the given module, which may be null.  When the module
	 * is null, this class will only looks for items on the classpath, under a 'help' directory.
	 *
	 * @param moduleDirectory the module directory to search; may be null
	 */
	public GHelpClassLoader(ResourceFile moduleDirectory) {
		super(GHelpClassLoader.class.getClassLoader());
		this.moduleDirectory = moduleDirectory;
	}

	/**
	 * Overridden to allow us to search our modules in addition to the normal class search
	 * mechanism.
	 *
	 * @param name the name of the help item to load
	 * @return the URL for the given item; null if the item cannot be found
	 */
	@Override
	protected URL findResource(String name) {
		URL url = super.findResource(name);
		if (url != null) {
			return url;
		}

		url = findInModuleDirectory(name);
		if (url != null) {
			return url;
		}

		return findInJarFile(name);
	}

	private URL findInJarFile(String name) {

		// installation/release usage--data is inside of a jar file
		URL URL = ResourceManager.getResource("help/" + name);
		if (URL != null) {
			return URL;
		}

		return null;
	}

	private URL findInModuleDirectory(String name) {
		if (moduleDirectory == null) {
			// must be the master loader
			return null;
		}

		// we have a specific module
		ResourceFile helpFile = new ResourceFile(moduleDirectory, name);
		if (helpFile.exists()) {
			try {
				return helpFile.toURL();
			}
			catch (MalformedURLException e) {
				Msg.error(this, "Unexpected exception converting file to URL: " + helpFile, e);
			}
		}
		return null;
	}
}
