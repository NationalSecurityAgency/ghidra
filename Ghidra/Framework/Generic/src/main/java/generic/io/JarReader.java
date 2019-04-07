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
package generic.io;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import utilities.util.FileUtilities;

/**
 * JarReader is a class for reading from a jar input stream.
 */
public class JarReader {

	protected JarInputStream jarIn;
	
	/** Creates a JarReader
	 * @param jarIn the the jar file input stream the zip entries are
	 * read from.
	 */
	public JarReader(JarInputStream jarIn) {
		this.jarIn = jarIn;
	}

    /**
     * Recursively reads the files from the jar input stream and creates the
     * respetive directories and files in the file system.
     * <P>It effectively unzips the Jar file.
     * Warning: This will overwrite any files that already exist on the file 
     * system as it outputs the jar contents.
     * 
     * @param basePath the base path for where to output the JarInputStream 
     * file contents to.
     * 
     * @throws  FileNotFoundException  if the file exists but is a directory
     *                   rather than a regular file, does not exist but cannot
     *                   be created, or cannot be opened for any other reason
     * @throws IOException if it can't read the jar file or output one
     * or more of its files.
     */
    public void createRecursively(String basePath, TaskMonitor monitor) 
    		throws FileNotFoundException, IOException {
    	boolean done = false;
    	
    	while (!done && !monitor.isCancelled()) {
	        //Get the zip entry.
	        JarEntry entry = jarIn.getNextJarEntry();
	        if (entry == null) {
	        	done = true;
	        	break;
	        }
	        String name = entry.getName();
	        long modTime = entry.getTime();
//	        long size = entry.getSize();
//	        String comment = entry.getComment();
	        
	        // Create the output file.
	        String filePath = basePath+name;
	        
	        // replace any embedded separator characters
	        //   with the separator char on this platform
	        filePath = filePath.replace('/', File.separatorChar);
			filePath = filePath.replace('\\', File.separatorChar);
			
	        long lastIndex = filePath.lastIndexOf(File.separatorChar);
	        String dirPath = filePath.substring(0, (int)lastIndex);
//	        String fileName = filePath.substring((int)(lastIndex+1));
	    	File dir = new File(dirPath);
	    	FileUtilities.mkdirs(dir);
	    	
	    	File file = new File(filePath);
	    	if (!file.createNewFile() && !file.exists()) {
	    		throw new IOException("Couldn't create file "+file.getAbsolutePath());
	    	}
	    	
	        // Write it out to the file along with its data.
	    	FileOutputStream out = null;

		    out = new FileOutputStream(file);

	        byte[] bytes = new byte[4096];
	        int numRead = 0;
	        try {       
		        while ((numRead = jarIn.read(bytes)) != -1 && 
		        	!monitor.isCancelled()) {
		           
		           out.write(bytes, 0 , numRead);
		        }
	        } finally {
	        	try {
	        		out.close();
	        	} catch (IOException ioe) {
	        	    Msg.error(this, "Unexpected Exception: " + ioe.getMessage(), ioe);
	        	}
	        }
	        
	        if (modTime > 0 && file.isFile()) {
	        	file.setLastModified(modTime);
	        }
	        
    	}
    	
    	// Fix directory times
    	fixDirModifiedTimes(new File(basePath));
    }
    
    private void fixDirModifiedTimes(File dir) {
    	long modTime = 0;
    	File[] files = dir.listFiles();
    	for (File f : files) {
			if (f.isDirectory()) {
				fixDirModifiedTimes(f);
			}
			long t = f.lastModified();
			if (t > modTime) {
				modTime = t;
			}
		}
    	if (modTime > 0) {
    		dir.setLastModified(modTime);
    	}
    }

    /** 
     * Return the jar input stream being used by this JarReader.
     */
    public JarInputStream getJarInputStream() {
    	return jarIn;
    }
    
}
