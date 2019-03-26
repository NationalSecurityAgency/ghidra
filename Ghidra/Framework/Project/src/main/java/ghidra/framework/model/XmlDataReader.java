/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.model;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.InvalidNameException;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import org.xml.sax.SAXException;

/**
 * Defines the method for creating an Object from an 
 * XML file in a JarInputStream.
 */
public interface XmlDataReader {

	/**
	 * Reads the XML file indicated by the base path and relative path name.
	 * It creates an object(s) from this, that is used by the project.
	 * 
	 * @param basePath the prefix part of the path for the XML file
	 * @param relPathName a pathname for the file relative to the basePath.
	 * @param removeFile on success this should remove the original file.
	 * @param monitor a monitor for providing progress information to the user.
	 * 
     * @return true if an object associated with the file was added to the
     * project. false if the file couldn't be processed.
     * 
     * @throws SAXException if the XML file has a XML parsing error.
     * @throws IOException if there is problem reading/removing the XML file
     * or if there is a problem creating any resulting file.
     * @throws NotFoundException if a required service can't be found in 
     * the service registry.
     */
    public boolean addXMLObject(PluginTool tool,
    							String basePath,
    							String relPathName,
    							boolean removeFile,
    							TaskMonitor monitor)
		throws NotFoundException, SAXException,DuplicateNameException, 
		   NotOwnerException, InvalidNameException, IOException;

    /**
     * Returns a string summarizing the results of the XML data read
     * or <code>null</code> if there was nothing to report.
     * 
     * @return a string summarizing the results of the xml data read
     *         or <code>null</code> if there was nothing to report
     */
    public String getSummary();
}
