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
package ghidra.bitpatterns.info;

import java.awt.Component;
import java.io.*;
import java.util.*;

import org.apache.commons.io.FileUtils;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.task.*;

/**
 * An object of this class stores information about function starts (and returns) to analyze.
 * 
 * <p> There are two possible sources for this information.  The first is a directory containing 
 * XML files produced by JAXB from FunctionBitPatternInfo objects.  The second is a single program.
 */

public class FileBitPatternInfoReader {

	private List<FunctionBitPatternInfo> fInfoList; //list of all function starts and returns to analyze
	private List<Long> startingAddresses; //list of all the starting addresses of the functions
	private ContextRegisterExtent registerExtent;//information about all context register values seen in all the xml files
	private int numFuncs = 0;//number of function seen in all the xml files
	private int numFiles = 0;//number of xml files in the directory
	private DataGatheringParams params;

	/**
	 * Gathers function start information from a program.
	 * 
	 * @param program The program to mine.
	 * @param params The parameters controlling how much information to gather.
	 * @param parent parent component
	 */
	public FileBitPatternInfoReader(Program program, DataGatheringParams params, Component parent) {
		startingAddresses = new ArrayList<Long>();
		fInfoList = new ArrayList<FunctionBitPatternInfo>();
		registerExtent = new ContextRegisterExtent();
		this.params = params;
		numFiles = 1;

		MineProgramTask mineTask = new MineProgramTask(program);
		new TaskLauncher(mineTask, parent);
	}

	/**
	 * Gathers function start information from a directory of XML-serialized {@link FunctionBitPatternInfo}
	 * objects
	 * @param xmlDir directory containing the xml files
	 * @param monitor
	 */
	public FileBitPatternInfoReader(File xmlDir, Component parent) {
		if (!xmlDir.isDirectory()) {
			throw new IllegalArgumentException(xmlDir.getName() + " is not a directory");
		}

		startingAddresses = new ArrayList<Long>();
		fInfoList = new ArrayList<FunctionBitPatternInfo>();
		registerExtent = new ContextRegisterExtent();

		File[] dataFiles = xmlDir.listFiles();
		ReadDirectoryTask readTask = new ReadDirectoryTask(dataFiles);
		new TaskLauncher(readTask, parent);
	}

	/**
	 * Constructor used for testing
	 * @param xmlDir
	 */
	FileBitPatternInfoReader(File xmlDir) {
		if (!xmlDir.isDirectory()) {
			throw new IllegalArgumentException(xmlDir.getName() + " is not a directory");
		}

		startingAddresses = new ArrayList<Long>();
		fInfoList = new ArrayList<FunctionBitPatternInfo>();
		registerExtent = new ContextRegisterExtent();
		params = null;

		Iterator<File> dataFiles = FileUtils.iterateFiles(xmlDir, null, false);
		while (dataFiles.hasNext()) {
			File dataFile = dataFiles.next();
			processXmlFile(dataFile);
		}
	}

	private void processFBPIList(List<FunctionBitPatternInfo> fList) {
		for (FunctionBitPatternInfo fInfo : fList) {
			numFuncs++;
			fInfoList.add(fInfo);
			//record the starting address
			startingAddresses.add(Long.parseUnsignedLong(fInfo.getAddress(), 16));
			//add the context register values to the context register extent
			registerExtent.addContextInfo(fInfo.getContextRegisters());
		}
	}

	/**
	 * Get the list of addresses of the functions
	 * @return the addresses
	 */
	public List<Long> getStartingAddresses() {
		return startingAddresses;
	}

	/**
	 * Get the total number of functions
	 * @return number of functions
	 */
	public int getNumFuncs() {
		return numFuncs;
	}

	/**
	 * Get the number of files examined
	 * @return number of files
	 */
	public int getNumFiles() {
		return numFiles;
	}

	/**
	 * Get the information gathered about context registers
	 * @return context register information
	 */
	public ContextRegisterExtent getContextRegisterExtent() {
		return registerExtent;
	}

	/**
	 * Get the list of {@link FunctionBitPatternInfo} objects, one object per function examined.
	 * @return a list of the gathered information
	 */
	public List<FunctionBitPatternInfo> getFInfoList() {
		return fInfoList;
	}

	/**
	 * Returns the list of starting addresses for functions which pass registerFilter
	 * @param registerFilter - the context register filter
	 * @return the list of functions passing the filter
	 */
	public List<Long> getFilteredAddresses(ContextRegisterFilter registerFilter) {
		List<Long> filteredAddresses = new ArrayList<Long>();
		for (FunctionBitPatternInfo fInfo : fInfoList) {
			if (registerFilter.allows(fInfo.getContextRegisters())) {
				filteredAddresses.add(Long.parseUnsignedLong(fInfo.getAddress(), 16));
			}
		}
		return filteredAddresses;
	}

	/**
	 * Get the parameters used to gather this information
	 * @return the data gathering paramaters
	 */
	public DataGatheringParams getDataGatheringParams() {
		return params;
	}

	private void processXmlFile(File dataFile) {
		if (!dataFile.getName().endsWith(".xml")) {
			Msg.info(this, "Skipping " + dataFile.getName());
			return;
		}
		numFiles++;

		FileBitPatternInfo fileInfo = null;
		try {
			fileInfo = FileBitPatternInfo.fromXmlFile(dataFile);
		}
		catch (IOException e) {
			Msg.error(this, "Error reading FileBitPatternInfo file " + dataFile, e);
			return;
		}

		if (fileInfo.getFuncBitPatternInfo() == null) {
			Msg.info(this, "fList.getFuncBitPatternInfoList null for " + dataFile);
			return;
		}

		if (params == null) {
			//TODO: this will set the params to the params of the first valid file
			//these should agree with the parameters for all of the files
			//warn user if they don't?
			params = new DataGatheringParams();
			params.setNumFirstBytes(fileInfo.getNumFirstBytes());
			params.setNumPreBytes(fileInfo.getNumPreBytes());
			params.setNumReturnBytes(fileInfo.getNumReturnBytes());
			params.setNumFirstInstructions(fileInfo.getNumFirstInstructions());
			params.setNumPreInstructions(fileInfo.getNumPreInstructions());
			params.setNumReturnInstructions(fileInfo.getNumReturnInstructions());
		}
		processFBPIList(fileInfo.getFuncBitPatternInfo());
	}

	/**
	 * Task for mining a single program 
	 */
	class MineProgramTask extends Task {

		private AddressSetView initialized;
		private FunctionIterator fIter;
		private List<FunctionBitPatternInfo> fList;
		private Program program;

		/**
		 * Creates a {@link Task} for mining function bit pattern information from a given program
		 * @param program source program
		 */
		public MineProgramTask(Program program) {
			super("Mining Program", true, true, true);
			this.program = program;
			initialized = program.getMemory().getLoadedAndInitializedAddressSet();
			fIter = program.getFunctionManager().getFunctions(true);
			fList = new ArrayList<>();

		}

		@Override
		public void run(TaskMonitor monitor) {
			monitor.setMaximum(program.getFunctionManager().getFunctionCount());
			while (fIter.hasNext() && !monitor.isCancelled()) {
				monitor.incrementProgress(1);
				Function func = fIter.next();
				if (func.isThunk()) {
					continue;
				}
				if (func.isExternal()) {
					continue;
				}
				if (!initialized.contains(func.getEntryPoint())) {
					continue;
				}
				if (program.getListing().getInstructionAt(func.getEntryPoint()) == null) {
					continue;
				}

				FunctionBitPatternInfo fStart = new FunctionBitPatternInfo(program, func, params);
				if (fStart.getFirstBytes() != null) {
					fList.add(fStart);
				}
			}
			processFBPIList(fList);
		}
	}

	/**
	 * {@link Task} for processing an array of XML-serialized FileBitPatternInfo objects
	 */
	class ReadDirectoryTask extends Task {
		private File[] dataFiles;

		/**
		 * Creates a Task for restoring an array of XML-serialized FileBitPatternInfo objects
		 * @param dataFiles array file files
		 * @param unmarshaller Unmarshaller for serialized xml 
		 */
		public ReadDirectoryTask(File[] dataFiles) {
			super("Reading XML", true, true, true);
			this.dataFiles = dataFiles;
		}

		@Override
		public void run(TaskMonitor monitor) {
			monitor.setMaximum(dataFiles.length);
			params = null;
			for (File dataFile : dataFiles) {
				monitor.incrementProgress(1);
				processXmlFile(dataFile);
			}
		}
	}
}
