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
/**
 * 
 */
package ghidra.sleigh.grammar;

import java.io.File;
import java.util.*;

/**
 * Utility class to Search for Files in any directory
 * All one needs is to call FileSearcher.gatherFilesFromDir and 
 * provide the necessary file extension(s) and the list will be returned.
 * 
 * 
 *
 */
public class FileSearcher {

	/***
	 * File Searcher Exception Handler...
	 * 
	 */
	public static class FileSearcherException extends Exception {
		public static final long serialVersionUID = 0L;
		public FileSearcherException(String ExceptionString) {
			super(ExceptionString);
		}
	}
	
	/***
	 * Gather's all Files from the Directory
	 * that have the passed in File Type Extension.
	 * Returns this List of Files Found.
	 * 
	 * @param currDirToSearch - The Directory to Search
	 * @param currFileTypeExtList - The List of File Type Extensions to Search for
	 * @param useRecursionInSearch - Determine whether to Search recursively or not
	 * @return - List of Files that were found
	 */
	public static final List<File> gatherFilesFromDir(File currDirToSearch,
			List<String> currFileTypeExtList, boolean useRecursionInSearch)
			throws FileSearcherException {
		List<File> foundFilesFromSearchList = new ArrayList<File>();

		//Sanity Checks before use!
		if (currDirToSearch == null) {
			throw new FileSearcherException("The Directory to Search cannot be NULL!");
		}
		else if (!currDirToSearch.isDirectory()) {
			throw new FileSearcherException(
				"The Directory must be a valid Directory! It currently is not!");
		}
		else if (currFileTypeExtList == null) {
			throw new FileSearcherException("File Type Extension list is NULL! " +
				"Must Provide at least 1 File Type Extension to search for!");
		}
		else if ((currFileTypeExtList.size() == 0) || (currFileTypeExtList.isEmpty())) {
			throw new FileSearcherException(
				"Must Provide at least 1 File Type Extension to search for!");
		}

		if (currDirToSearch.isDirectory()) { //Another Sanity check!
			File[] currDirToSearchRoot = currDirToSearch.listFiles();
			locateFilesFromDirRoot(currDirToSearchRoot, currFileTypeExtList,
				foundFilesFromSearchList, useRecursionInSearch);
		}
		return foundFilesFromSearchList;
	}
	
	/***
	 * Performs the location of files of type FileTypeExtension passed in, whether recursively
	 * or not, and stores these files in the currFilesFromSearchList parameter.
	 * 
	 * @param currDirArray - The Directory Root Array of Files.
	 * @param currFileTypeExtList - The List of File Type Extensions to Search for
	 * @param currFilesFromSearchList - File List to add found Files to.
	 * @param recursiveSearch - Determine whether to Search recursively or not
	 */
	private static final void locateFilesFromDirRoot(File [] currDirArray, List<String> currFileTypeExtList, List<File> currFilesFromSearchList, boolean recursiveSearch){
		List<File> currDirRootList = new ArrayList<File>();
		currDirRootList.addAll( Arrays.asList( currDirArray ) );
		//No Sanity Checks needed as this is a private member and used internally...
		for(File currFile : currDirRootList){
			if(currFile.isDirectory()){
				if(recursiveSearch) {//RECURSION!!!
					File [] currFileDirArray = currFile.listFiles();
					locateFilesFromDirRoot(currFileDirArray, currFileTypeExtList, currFilesFromSearchList, recursiveSearch);
				}
			}else{
				for(String currFileTypeExt : currFileTypeExtList) {
					if(currFile.getName().endsWith(currFileTypeExt)){
						currFilesFromSearchList.add(currFile);
					}
				}
			}
		}
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
