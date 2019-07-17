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
package ghidra.test;

import java.io.*;

/**
 * Compile a java file; deletes the java file and the class file when the
 * junit exits.
 * 
 * 
 */
public class JavaCompiler {

	private IOThread cmdOut;
	private IOThread cmdErr;

	/**
	 * Compile a java file.
	 */
	public void compile(File javaFile) { 
		String name = javaFile.getName();
		String className = name.substring(0, name.indexOf(".")) + ".class";
		
		File parent = javaFile.getParentFile();
		String parentPath = parent.getAbsolutePath();
		int pos = parentPath.lastIndexOf("ghidra");
		String destPath = parentPath.substring(0, pos-1);
		
		javaFile.deleteOnExit();
		
		File classFile = new File(parent, className);
		classFile.deleteOnExit();
		
		String classpath = System.getProperty("java.class.path");
		String javaLoc = System.getProperty("java.home");
		if (javaLoc.endsWith("jre")) {
			javaLoc = javaLoc.substring(0, javaLoc.indexOf("jre")-1);
		}
		String argV[] = new String[6];
		argV[0] = javaLoc + File.separator + "bin" + File.separator +"javac";
		argV[1] = "-classpath";
		argV[2] = classpath;
		argV[3] = "-d";
		argV[4] = destPath;
		argV[5] = javaFile.getAbsolutePath(); 
		try {
			Process p = Runtime.getRuntime().exec(argV);
			for (int i=0; i<argV.length; i++) {
				System.out.print(argV[i] + " ");
			}
			System.out.println();
				
			InputStream stderrStream = p.getErrorStream();
			InputStream stdinStream  = p.getInputStream();
		    
			setupIO(stdinStream, stderrStream);
			p.waitFor();
	        
			cmdOut.join();
			cmdErr.join();

		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Set up threads to read from stdin and stderr and output that
	 * to stdout.
	 * @param stdin
	 * @param stderr
	 */
	private void setupIO (InputStream stdin, InputStream stderr){
		cmdOut = new IOThread(stdin); // 
		cmdErr = new IOThread(stderr);
		cmdOut.start();
		cmdErr.start();
	}

	/**
	 * 
	 * Thread to read from an input stream and write it to stdout.
	 */
	private class IOThread extends Thread {
		private BufferedReader shellOutput;

		public IOThread (InputStream input) {
			shellOutput = new  BufferedReader(new InputStreamReader(input));
		}

		@Override
        public void run() {
			String line = null;
			try {
				while ((line = shellOutput.readLine()) != null) {
					System.out.println(line);
				}
			}
			catch(Exception e) {
				e.printStackTrace();
			}

		}
	}
}
