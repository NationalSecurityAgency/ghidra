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
package ghidra;

import java.io.*;

/**
 * JunitTestScan scans for 0-length JUnit xsl data files and fills in the file 
 * with minimal error data.
 */
public class JunitTestScan {
	
	private static final FilenameFilter TEST_XML_FILTER = new FilenameFilter() {
		public boolean accept(File dir, String name) {
			return (name.startsWith("TEST-") && name.endsWith(".xml"));
		}
	};
	
	private static void writeXmlFile(File xmlFile) throws IOException {
		
		String className = xmlFile.getName().substring(5);
		className = className.substring(0, className.lastIndexOf(".xml"));
		
		BufferedWriter w = new BufferedWriter(new FileWriter(xmlFile));
		w.write("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n");
		w.write("<testsuite errors=\"0\" failures=\"1\" name=\"" + className + "\" tests=\"1\" time=\"0\">\n");
		w.write("<testcase name=\"UNKNOWN ERROR\" time=\"0\">\n");
		w.write("<error message=\"JVM exited prematurely preventing JUnit from properly reporting test results\" type=\"System Exit Error\"></error>\n");
		w.write("</testcase>\n");
		w.write("</testsuite>\n");
		w.close();
	}
	

	public static void main(String[] args) {
		
		if (args.length != 1) {
			System.err.println("Incorrect usage!");	
			System.exit(-1);
		}
		
		File dataDir = new File(args[0]);
		if (!dataDir.isDirectory()) {
			System.err.println(args[0] + " is not a valid directory");	
			System.exit(-1);
		}
		
		File[] files = dataDir.listFiles(TEST_XML_FILTER);
		for (int i = 0; i < files.length; i++) {
			if (files[i].length() == 0) {
				try {
					System.out.println("Found bad test data: " + files[i]);
					writeXmlFile(files[i]);	
				} catch (IOException e) {
					System.err.println("Failed to fix data file: " + files[i]);	
				}
			}	
		}
		
		
	}
}
