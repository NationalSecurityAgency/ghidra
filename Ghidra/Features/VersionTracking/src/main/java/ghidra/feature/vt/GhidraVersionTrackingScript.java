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
package ghidra.feature.vt;

import java.io.IOException;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public abstract class GhidraVersionTrackingScript extends GhidraScript {
	protected VTSession vtSession;
	protected Program sourceProgram;
	protected Program destinationProgram;

	private int transactionID;

	public void createVersionTrackingSession(String sourceProgramPath, String destinationProgramPath)
			throws Exception {

		if (vtSession != null) {
			throw new RuntimeException("Attempted to open a new session with one already open!");
		}
		sourceProgram = openProgram(sourceProgramPath);
		destinationProgram = openProgram(destinationProgramPath);

		createVersionTrackingSession("New Session", sourceProgram, destinationProgram);
	}

	public void createVersionTrackingSession(String name, Program source, Program destination)
			throws Exception {

		if (vtSession != null) {
			throw new RuntimeException("Attempted to create a new session with one already open!");
		}
		sourceProgram = source;
		destinationProgram = destination;

		if (!sourceProgram.isUsedBy(this)) {
			sourceProgram.addConsumer(this);
		}
		if (!destinationProgram.isUsedBy(this)) {
			destinationProgram.addConsumer(this);
		}

		vtSession = VTSessionDB.createVTSession(name, sourceProgram, destinationProgram, this);
		transactionID = vtSession.startTransaction("VT Script");
	}

	public void openVersionTrackingSession(String path) throws Exception {
		if (vtSession != null) {
			throw new RuntimeException("Attempted to open a session with one already open!");
		}

		if (state.getProject() == null) {
			throw new RuntimeException("No project open.");
		}
		DomainFile file = state.getProject().getProjectData().getFile(path);
		vtSession = (VTSessionDB) file.getDomainObject(this, true, true, monitor);
		sourceProgram = vtSession.getSourceProgram();
		destinationProgram = vtSession.getDestinationProgram();

		if (!sourceProgram.isUsedBy(this)) {
			sourceProgram.addConsumer(this);
		}
		if (!destinationProgram.isUsedBy(this)) {
			destinationProgram.addConsumer(this);
		}
		transactionID = vtSession.startTransaction("VT Script");
	}

	public void saveVersionTrackingSession() throws IOException {
		vtSession.endTransaction(transactionID, true);
		vtSession.save();
		transactionID = vtSession.startTransaction("VT Script");
	}

	public void saveSessionAs(String path, String name) throws Exception {
		DomainFolder folder = state.getProject().getProjectData().getFolder(path);
		folder.createFile(name, vtSession, monitor);
		vtSession.setName(name);
	}

	@Override
	public void cleanup(boolean success) {
		closeVersionTrackingSession();
		if (destinationProgram != null) {
			closeProgram(destinationProgram);
		}
		if (sourceProgram != null) {
			closeProgram(sourceProgram);
		}
		sourceProgram = null;
		destinationProgram = null;
	}

	public void closeVersionTrackingSession() {
		if (vtSession != null) {
			vtSession.endTransaction(transactionID, true);
			vtSession.release(this);
		}

	}

	public Program openProgram(String path) throws VersionException, CancelledException,
			IOException {
		if (state.getProject() == null) {
			throw new RuntimeException("No project open.");
		}
		DomainFile file = state.getProject().getProjectData().getFile(path);
		return (Program) file.getDomainObject(this, true, true, monitor);
	}

	@Override
	public void closeProgram(Program program) {
		program.release(this);
	}

	public Set<String> getSourceFunctions() {
		if (vtSession == null) {
			throw new RuntimeException("You must have an open vt session");
		}
		return getFunctionNames(vtSession.getSourceProgram());
	}

	public Set<String> getDestinationFunctions() {
		if (vtSession == null) {
			throw new RuntimeException("You must have an open vt session");
		}
		return getFunctionNames(vtSession.getSourceProgram());
	}

	private Set<String> getFunctionNames(Program program) {
		Set<String> functionNames = new HashSet<String>();
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		for (Function function : functions) {
			functionNames.add(function.getName());
		}
		return functionNames;
	}

	public List<String> getProgramCorrelators() {
		List<String> correlators = new ArrayList<String>();
		List<VTProgramCorrelatorFactory> generateList = getVTProgramCorrelatorFactory();
		for (VTProgramCorrelatorFactory vtProgramCorrelatorFactory : generateList) {
			correlators.add(vtProgramCorrelatorFactory.getName());
		}
		return correlators;
	}

	public void runCorrelator(String name) throws CancelledException {
		if (vtSession == null) {
			throw new RuntimeException("You must have an open vt session to run a correlator");
		}
		VTProgramCorrelatorFactory correlatorFactory = getCorrelatorFactory(name);
		VTProgramCorrelator correlator =
			correlatorFactory.createCorrelator(null, sourceProgram,
				sourceProgram.getMemory().getLoadedAndInitializedAddressSet(), destinationProgram,
				destinationProgram.getMemory().getLoadedAndInitializedAddressSet(), new VTOptions("dummy"));
		correlator.correlate(vtSession, monitor);

	}

	public Collection<VTMatch> getMatchesFromLastRunCorrelator() {
		List<VTMatchSet> matchSets = vtSession.getMatchSets();
		VTMatchSet last = matchSets.get(matchSets.size() - 1);
		return last.getMatches();

	}

	public Function getSourceFunction(VTMatch vtMatch) {
		VTAssociation association = vtMatch.getAssociation();
		Program source = vtSession.getSourceProgram();
		FunctionManager functionManager = source.getFunctionManager();
		return functionManager.getFunctionAt(association.getSourceAddress());
	}

	public Function getDestinationFunction(VTMatch vtMatch) {
		VTAssociation association = vtMatch.getAssociation();
		Program destination = vtSession.getDestinationProgram();
		FunctionManager functionManager = destination.getFunctionManager();
		return functionManager.getFunctionAt(association.getDestinationAddress());
	}

//==================================================================================================
// Potential Methods
//==================================================================================================	

// to not correlate the entire program	
//	public void runCorrelator(String name, AddressSet addresSet)

	// TODO
	// -a way to allow users to apply markup of matches, given some filtering criteria 
	// (maybe via a callback)
	// -a way to allow users to specify the **options** for applying, since this is how
	// we perform applying now 

//==================================================================================================
// Private Methods
//==================================================================================================	

	private VTProgramCorrelatorFactory getCorrelatorFactory(String name) {
		List<VTProgramCorrelatorFactory> generateList = getVTProgramCorrelatorFactory();
		for (VTProgramCorrelatorFactory vtProgramCorrelatorFactory : generateList) {
			if (vtProgramCorrelatorFactory.getName().equals(name)) {
				return vtProgramCorrelatorFactory;
			}
		}
		return null;
	}

	private static List<VTProgramCorrelatorFactory> getVTProgramCorrelatorFactory() {
		return ClassSearcher.getInstances(VTProgramCorrelatorFactory.class);
	}
}
