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
package ghidra.framework.store;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;

/**
 * <code>ItemCheckoutStatus</code> provides immutable status information for a 
 * checked-out item.  This class is serializable so that it may be passed 
 * to a remote client.
 */
public class ItemCheckoutStatus implements java.io.Serializable {

	public static final long serialVersionUID = 1L;

	private static final int VERSION = 3;

	private long checkoutId;
	private String user;
	private int version;
	private long time;
	private String projectPath;
	private CheckoutType checkoutType;

	/**
	 * Constructor.
	 * @param checkoutId unique checkout ID
	 * @param checkoutType type of checkout
	 * @param user user name
	 * @param version version of file which was checked-out
	 * @param time time when checkout was completed.
	 */
	public ItemCheckoutStatus(long checkoutId, CheckoutType checkoutType, String user, int version,
			long time, String projectPath) {
		this.checkoutId = checkoutId;
		this.checkoutType = checkoutType;
		this.user = user;
		this.version = version;
		this.time = time;
		if (projectPath != null) {
			projectPath = projectPath.replace('\\', '/');
		}
		this.projectPath = projectPath;
	}

	/**
	 * Serialization method
	 * @param out
	 * @throws IOException
	 */
	private void writeObject(java.io.ObjectOutputStream out) throws IOException {
		out.writeInt(VERSION);
		out.writeLong(checkoutId);
		out.writeUTF(user);
		out.writeInt(version);
		out.writeLong(time);
		out.writeInt(checkoutType.getID());
		out.writeUTF(projectPath != null ? projectPath : "");
	}

	/**
	 * Deserialization method
	 * @param in
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	private void readObject(java.io.ObjectInputStream in) throws IOException,
			ClassNotFoundException {
		long ver = in.readInt();
		if (ver > VERSION) {
			throw new ClassNotFoundException("Unsupported version of ItemCheckoutStatus");
		}
		checkoutId = in.readLong();
		user = in.readUTF();
		version = in.readInt();
		time = in.readLong();
		if (ver < 3) {
			checkoutType = in.readBoolean() ? CheckoutType.EXCLUSIVE : CheckoutType.NORMAL;
		}
		else { // Transient checkout added with Version 3
			int checkoutTypeId = in.readInt();
			checkoutType = CheckoutType.getCheckoutType(checkoutTypeId);
			if (checkoutType == null) {
				throw new IOException("Invalid ItemCheckoutStatus Type: " + checkoutTypeId);
			}
		}
		if (ver > 1) { // Client project path added with Version 2
			projectPath = in.readUTF();
			if (projectPath.length() == 0) {
				projectPath = null;
			}
		}
	}

	/**
	 * Returns the unique ID for the associated checkout.
	 */
	public long getCheckoutId() {
		return checkoutId;
	}

	/**
	 * Returns the checkout type
	 * @return checkout type
	 */
	public CheckoutType getCheckoutType() {
		return checkoutType;
	}

	/**
	 * Returns the user name for the associated checkout.
	 */
	public String getUser() {
		return user;
	}

	/**
	 * Returns the file version which was checked-out.
	 */
	public int getCheckoutVersion() {
		return version;
	}

	/**
	 * Returns the time at which the checkout was completed.
	 */
	public long getCheckoutTime() {
		return time;
	}

	/**
	 * Returns the time at which the checkout was completed.
	 * @return
	 */
	public Date getCheckoutDate() {
		return new Date(time);
	}

	/**
	 * Returns user's local project path if known.
	 */
	public String getProjectPath() {
		return projectPath;
	}

	/**
	 * Return a Project location which corresponds to the projectPath 
	 * or null if one can not be constructed.
	 * @return project location
	 */
	public String getProjectName() {
		if (projectPath == null) {
			return null;
		}
		String path = projectPath;
		int ix = path.indexOf("::");
		if (ix > 0) {
			path = path.substring(ix + 2);
		}
		ix = path.lastIndexOf('/');
		if (ix < 0) {
			return null;
		}
		return path.substring(ix + 1);
	}

	/**
	 * Return a Project location which corresponds to the projectPath 
	 * or null if one can not be constructed.
	 * @return project location
	 */
	public String getProjectLocation() {
		if (projectPath == null) {
			return null;
		}
		String path = projectPath;
		int ix = path.indexOf("::");
		if (ix > 0) {
			path = path.substring(ix + 2);
		}
		ix = path.lastIndexOf('/');
		if (ix < 0) {
			return null;
		}
		return path.substring(0, ix);
	}

	/**
	 * Returns the user's hostname associated with the original checkout
	 * @return host name or null
	 */
	public String getUserHostName() {
		if (projectPath == null) {
			return null;
		}
		int ix = projectPath.indexOf("::");
		if (ix > 0) {
			return projectPath.substring(0, ix);
		}
		return null;
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (checkoutId ^ (checkoutId >>> 32));
		result = prime * result + (int) (time ^ (time >>> 32));
		result = prime * result + ((user == null) ? 0 : user.hashCode());
		result = prime * result + version;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		
		if (!(obj instanceof ItemCheckoutStatus)) {
			return false;
		}
		ItemCheckoutStatus other = (ItemCheckoutStatus) obj;
		return checkoutId == other.checkoutId && user.equals(other.user) &&
			version == other.version && time != other.time;
	}

	/**
	 * Get project path string suitable for checkout requests
	 * @param projectPath
	 * @param isTransient true if project is transient
	 * @return project location path
	 */
	public static String getProjectPath(String projectPath, boolean isTransient) {
		String hostname = "";
		try {
			hostname = InetAddress.getLocalHost().getHostName() + "::";
		}
		catch (UnknownHostException e1) {
			hostname = "<standalone>::";
		}
		if (isTransient) {
			return hostname + "<Transient>";
		}
		return hostname + projectPath;
	}

}
