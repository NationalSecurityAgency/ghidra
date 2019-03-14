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

/**
 * <code>Version</code> provides immutable information about a specific version of an item.
 */
public class Version implements java.io.Serializable {

	public static final long serialVersionUID = 1L;
	
	private static final int VERSION = 1;
	
	private int version;
	private long createTime;
	private String user;
	private String comment;
	
	/**
	 * Constructor.
	 * @param version file version number
	 * @param createTime time version was created
	 * @param user name of user who created version
	 * @param comment version comment
	 */
	public Version(int version, long createTime, String user, String comment) {
		this.version = version;
		this.createTime = createTime;
		this.user = user;
		this.comment = comment;	
	}
	
	/**
	 * Serialization method
	 * @param out
	 * @throws IOException
	 */
	private void writeObject(java.io.ObjectOutputStream out) throws IOException {
		out.writeInt(VERSION);
		out.writeInt(version);
		out.writeLong(createTime);
		out.writeUTF(user);
		out.writeUTF(comment  != null ? comment : "");
	}
	
	/**
	 * Deserialization method
	 * @param in
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
 	private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
 		long ver = in.readInt();
 		if (ver > VERSION) {
 			throw new ClassNotFoundException("Unsupported version of Version");
 		}
		version = in.readInt();
		createTime = in.readLong();
		user = in.readUTF();
		comment = in.readUTF();
 	}
 	
 	/**
 	 * Returns version number.
 	 */
	public int getVersion() {
		return version;
	}
	
	/**
	 * Returns time at which version was created.
	 */
	public long getCreateTime() {
		return createTime;
	}
	
	/**
	 * Returns version comment.
	 */
	public String getComment() {
		return comment;
	}
	
	/**
	 * Returns name of user who created version.
	 */
	public String getUser() {
		return user;
	}
	
}
