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
package ghidra.framework;

/**
 * Class to represent an application's unique identifier.  An application identifier is made up
 * of an application name, an application version, and an application release name.
 * <pre>
 * The identifier format is (\.+) - \d\.\d(\.\d)?(\-.+)? _ (\.+)
 *                          name         version        release name
 * </pre>
 * Application names will be converted to all lowercase and application release names will be
 * converted to all uppercase.  Both will have spaces removed from their names.
 * <p>
 * Examples:
 * <ul>
 * <li>ghidra-7.4_DEV
 * </ul>
 */
public class ApplicationIdentifier {

	private String applicationName;
	private ApplicationVersion applicationVersion;
	private String applicationReleaseName;

	/**
	 * Creates a new {@link ApplicationIdentifier} object from an {@link ApplicationProperties}.
	 * 
	 * @param applicationProperties An {@link ApplicationProperties}.
	 * @throws IllegalArgumentException if required elements from the {@link ApplicationProperties} 
	 *   were missing or otherwise failed to parse.  The exception's message has more detailed 
	 *   information about why it failed.
	 */
	public ApplicationIdentifier(ApplicationProperties applicationProperties)
			throws IllegalArgumentException {
		applicationName =
			applicationProperties.getApplicationName().replaceAll("\\s", "").toLowerCase();
		if (applicationName.isEmpty()) {
			throw new IllegalArgumentException("Application name is undefined.");
		}
		
		applicationVersion = new ApplicationVersion(applicationProperties.getApplicationVersion());

		applicationReleaseName =
			applicationProperties.getApplicationReleaseName().replaceAll("\\s", "").toUpperCase();
		if (applicationReleaseName.isEmpty()) {
			throw new IllegalArgumentException("Application release name is undefined.");
		}
	}

	/**
	 * Creates a new {@link ApplicationIdentifier} object from the given string.
	 * 
	 * @param identifier An identifier string.
	 * @throws IllegalArgumentException if the identifier string failed to parse.  The 
	 *   exception's message has more detailed information about why it failed.
	 */
	public ApplicationIdentifier(String identifier) throws IllegalArgumentException {
		parse(identifier);
	}

	/**
	 * Gets the application name.
	 * 
	 * @return The application name.
	 */
	public String getApplicationName() {
		return applicationName;
	}

	/**
	 * Gets the {@link ApplicationVersion application version}.
	 * 
	 * @return The {@link ApplicationVersion application version}.
	 */
	public ApplicationVersion getApplicationVersion() {
		return applicationVersion;
	}

	/**
	 * Gets the application release name.
	 * 
	 * @return The application release name.
	 */
	public String getApplicationReleaseName() {
		return applicationReleaseName;
	}

	@Override
	public String toString() {
		return applicationName + "_" + applicationVersion + "_" + applicationReleaseName;
	}

	@Override
	public int hashCode() {
		return (applicationName + applicationReleaseName).hashCode() *
			applicationVersion.hashCode();
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
		ApplicationIdentifier other = (ApplicationIdentifier) obj;
		if (!applicationName.equals(other.applicationName)) {
			return false;
		}
		if (!applicationReleaseName.equals(other.applicationReleaseName)) {
			return false;
		}
		if (!applicationVersion.equals(other.applicationVersion)) {
			return false;
		}
		return true;
	}

	/**
	 * Parses application identifier components out of the given version string.
	 * 
	 * @param identifier An identifier string.
	 * @throws IllegalArgumentException if the identifier string failed to parse.  The 
	 *   exception's message has more detailed information about why it failed.
	 */
	private void parse(String identifier) throws IllegalArgumentException {
		if (identifier == null) {
			throw new IllegalArgumentException("Identifier is null");
		}

		String[] identifierParts = identifier.split("_");
		if (identifierParts.length >= 3) {
			applicationName = identifierParts[0].replaceAll("\\s", "").toLowerCase();
			applicationVersion = new ApplicationVersion(identifierParts[1]);
			applicationReleaseName = identifierParts[2].replaceAll("\\s", "").toUpperCase();
			// Ignore any parts after the release name...they are not part of the identifier
		}
		else {
			throw new IllegalArgumentException(
				"Identifier has " + identifierParts.length + " parts but 3 are required");
		}
	}
}
