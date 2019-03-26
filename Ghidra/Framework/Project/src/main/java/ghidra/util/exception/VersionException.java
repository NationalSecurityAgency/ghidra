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
package ghidra.util.exception;

/**
 * Exception thrown when an object's version does not match its expected version.
 */
public class VersionException extends UsrException {

	/**
	 * Object created with unknown software version.
	 */
	public static final int UNKNOWN_VERSION = 0;

	/**
	 * Object created with older software version.
	 */
	public static final int OLDER_VERSION = 1;

	/**
	 * Object created with newer software version.
	 */
	public static final int NEWER_VERSION = 2;

	private boolean upgradeable = false;
	private int versionIndicator = UNKNOWN_VERSION;

	private String detailMessage = null;

	/**
	 * Constructor - not upgradeable
	 */
	public VersionException() {
		this(false);
	}

	/**
	 * Constructor - not upgradeable
	 * @param msg detailed message
	 */
	public VersionException(String msg) {
		super(msg);
	}

	/**
	 * Constructor.
	 * @param upgradable true indicates that an upgrade is possible.
	 * If true the version indicator value is set to OLDER_VERSION, if false
	 * it is set to UNKNOWN_VERSION.
	 */
	public VersionException(boolean upgradable) {
		super(getDefaultMessage(upgradable));
		this.upgradeable = upgradable;
		this.versionIndicator = upgradable ? OLDER_VERSION : UNKNOWN_VERSION;
	}

	/**
	 * Constructor.
	 * @param versionIndicator OLDER_VERSION, NEWER_VERSION or UNKNOWN_VERSION
	 * @param upgradable true indicates that an upgrade is possible.
	 */
	public VersionException(int versionIndicator, boolean upgradable) {
		this(upgradable);
		this.versionIndicator = versionIndicator;
	}

	/**
	 * Constructor.
	 * @param msg detailed message
	 * @param versionIndicator OLDER_VERSION, NEWER_VERSION or UNKNOWN_VERSION
	 * @param upgradable true indicates that an upgrade is possible.
	 */
	public VersionException(String msg, int versionIndicator, boolean upgradable) {
		this(msg);
		this.versionIndicator = versionIndicator;
		this.upgradeable = upgradable;
	}

	private static String getDefaultMessage(boolean upgradable) {
		if (upgradable) {
			return "data created with older software and requires upgrade";
		}
		return "data created with newer version and can not be read";
	}

	/**
	 * Return true if the file can be upgraded to the current version.
	 */
	public boolean isUpgradable() {
		return upgradeable;
	}

	/**
	 * Return a version indicator (OLDER_VERSION, NEWER_VERSION or UNKNOWN_VERSION).
	 * Only an OLDER_VERSION has the possibility of being upgradeable.
	 */
	public int getVersionIndicator() {
		return versionIndicator;
	}

	/**
	 * Combine another VersionException with this one.
	 * @param ve another version exception
	 * @return this combined version exception
	 */
	public VersionException combine(VersionException ve) {
		if (ve != null) {
			if (this.versionIndicator != ve.versionIndicator)
				versionIndicator = UNKNOWN_VERSION;
			upgradeable = upgradeable & ve.upgradeable;
			if (detailMessage == null) {
				detailMessage = ve.detailMessage;
			}
			else if (ve.detailMessage != null) {
				detailMessage += "\n" + ve.detailMessage;
			}
		}
		return this;
	}

	public void setDetailMessage(String message) {
		this.detailMessage = message;
	}

	public String getDetailMessage() {
		return detailMessage;
	}
}
