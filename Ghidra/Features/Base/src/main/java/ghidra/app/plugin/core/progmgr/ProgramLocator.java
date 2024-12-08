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
package ghidra.app.plugin.core.progmgr;

import java.io.IOException;
import java.net.URL;
import java.util.Objects;

import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Program;

/** 
 * Programs locations can be specified from either a {@link DomainFile} or a ghidra {@link URL}.
 * This class combines the two ways to specify the location of a program into a single object. The
 * DomainFile or URL will be normalized, so that this ProgramLocator can be used as a key that 
 * uniquely represents the program, even if the location is specified from different
 * DomainFiles or URLs that represent the same program instance.
 * <P>
 * The class must specify either a DomainFile or a URL, but not both.
 */
public class ProgramLocator {
	private final DomainFile domainFile;
	private final URL ghidraURL;
	private final int version;
	private final boolean invalidContent;

	/**
	 * Creates a {@link URL} based ProgramLocator. The URL must be using the Ghidra protocol
	 * @param url the URL to a Ghidra Program
	 */
	public ProgramLocator(URL url) {
		Objects.requireNonNull(url, "URL can't be null");
		if (!GhidraURL.isGhidraURL(url)) {
			throw new IllegalArgumentException("unsupported protocol: " + url.getProtocol());
		}
		this.ghidraURL = GhidraURL.getNormalizedURL(url);
		this.domainFile = null;
		this.version = DomainFile.DEFAULT_VERSION;
		this.invalidContent = false; // unable to validate
	}

	/**
	 * Creates a {@link DomainFile} based based ProgramLocator for the current version of a Program.
	 * @param domainFile the DomainFile for a program
	 */
	public ProgramLocator(DomainFile domainFile) {
		this(domainFile, DomainFile.DEFAULT_VERSION);
	}

	/**
	 * Creates a {@link DomainFile} based based ProgramLocator for a specific Program version.
	 * @param domainFile the DomainFile for a program
	 * @param version the specific version of the program
	 */
	public ProgramLocator(DomainFile domainFile, int version) {
		this.version = version;
		this.invalidContent = !Program.class.isAssignableFrom(domainFile.getDomainObjectClass());

		DomainFile file = null;
		URL url = null;

		DomainFolder parent = domainFile.getParent();
		if (invalidContent || version != DomainFile.DEFAULT_VERSION || parent == null ||
			parent.isInWritableProject()) {
			file = domainFile;
		}
		else {
			try {
				url = GhidraURL.getNormalizedURL(resolveURL(domainFile));
			}
			catch (IOException e) {
				file = domainFile;
			}
		}
		this.domainFile = file;
		this.ghidraURL = url;
	}

	/**
	 * Returns the DomainFile for this locator or null if this is a URL based locator
	 * @return the DomainFile for this locator or null if this is a URL based locator
	 */
	public DomainFile getDomainFile() {
		return domainFile;
	}

	/**
	 * Returns the URL for this locator or null if this is a DomainFile based locator
	 * @return the URL for this locator or null if this is a DomainFile based locator
	 */
	public URL getURL() {
		return ghidraURL;
	}

	/**
	 * Returns the version of the program that this locator represents
	 * @return the version of the program that this locator represents
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Returns true if this is a DomainFile based program locator
	 * @return true if this is a DomainFile based program locator
	 */
	public boolean isDomainFile() {
		return domainFile != null;
	}

	/**
	 * Returns true if this is a URL based program locator
	 * @return true if this is a URL based program locator
	 */
	public boolean isURL() {
		return ghidraURL != null;
	}

	/**
	 * Returns true if this ProgramLocator represents a valid program location
	 * @return true if this ProgramLocator represents a valid program location
	 */
	public boolean isValid() {
		return !invalidContent;
	}

	/**
	 * Returns true if the information in this location can be used to reopen a program.
	 * @return true if the information in this location can be used to reopen a program
	 */
	public boolean canReopen() {
		return !invalidContent && !(domainFile instanceof DomainFileProxy);
	}

	@Override
	public String toString() {
		if (domainFile != null) {
			return domainFile.toString();
		}
		return ghidraURL.toString();
	}

	@Override
	public int hashCode() {
		return Objects.hash(domainFile, ghidraURL, version);
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
		ProgramLocator other = (ProgramLocator) obj;
		return Objects.equals(domainFile, other.domainFile) &&
			Objects.equals(ghidraURL, other.ghidraURL) && version == other.version;
	}

	private URL resolveURL(DomainFile file) throws IOException {
		if (file.isLinkFile()) {
			return LinkHandler.getURL(file);
		}
		DomainFolder parent = file.getParent();
		if (file instanceof LinkedDomainFile linkedFile) {
			return resolveLinkedDomainFile(linkedFile);
		}
		if (!parent.getProjectLocator().isTransient()) {
			return file.getLocalProjectURL(null);
		}
		return file.getSharedProjectURL(null);
	}

	private URL resolveLinkedDomainFile(LinkedDomainFile linkedFile) {
		URL url = linkedFile.getLocalProjectURL(null);
		if (url == null) {
			url = linkedFile.getSharedProjectURL(null);
		}
		return url;
	}
}
