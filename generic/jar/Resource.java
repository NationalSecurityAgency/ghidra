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
package generic.jar;

import java.io.*;
//
import java.net.*;

public interface Resource {

	Resource getResource(String name);

	String getAbsolutePath();

	ResourceFile[] listFiles();

	ResourceFile[] listFiles(ResourceFileFilter filter);

	String getName();

	boolean isDirectory();

	Resource getParent();

	URL toURL() throws MalformedURLException;

	long lastModified();

	InputStream getInputStream() throws FileNotFoundException, IOException;

	boolean delete();

	boolean exists();

	OutputStream getOutputStream() throws FileNotFoundException;

	File getFile();

	long length();

	String getCanonicalPath() throws IOException;

	boolean isFile();

	Resource getCanonicalResource();

	boolean canWrite();

	boolean mkdir();

	File getFileSystemRoot();

	URI toURI();

	File getResourceAsFile(ResourceFile resourceFile);

}
