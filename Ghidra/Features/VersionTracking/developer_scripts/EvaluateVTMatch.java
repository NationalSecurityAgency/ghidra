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
import java.io.IOException;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class EvaluateVTMatch extends GhidraScript {
	// NOTE: this script is very rudimentary and makes a lot of assumptions,
	// such as unique symbol names in source and destination, that the
	// same-named symbols are actual matches, etc.
	//
	// Perhaps it should be based on manual matches as ground-truth.
	private static class MyFunction {
		public String name;
		public int srchits;
		public int desthits;
		public boolean matched;
		public boolean mismatched;
		public boolean srcexists;
		public boolean destexists;
		public boolean srcbody;
		public boolean destbody;

		public MyFunction(String nm) {
			name = nm;
			srchits = 0;
			desthits = 0;
			matched = false;
			mismatched = false;
			srcexists = false;
			destexists = false;
			srcbody = false;
			destbody = false;
		}
	}

	private static class VTScorer {
		private Program sourceProg;
		private Program destProg;
		private TreeMap<String, MyFunction> nameset;
		private FunctionManager sourceFuncMgr;
		private FunctionManager destFuncMgr;
		private int totalmatches;
		private int possiblematches;
		private int emptybodymatches;			// A pair (with same name) neither of which have a body, not considered a possiblematch
		private int othersrcfuncs;
		private int otherdestfuncs;
		private int conflicts;
		private int matchdiscovered;
		private int mismatch;
		private double falsenegative;
		private double falsepositive;
		private List<String> mismatchList;
		private int mismatchCountDown;
		
		public VTScorer(Program src,Program dest) {
			sourceProg = src;
			destProg = dest;
			nameset = new TreeMap<String,MyFunction>();
			sourceFuncMgr = sourceProg.getFunctionManager();
			destFuncMgr = destProg.getFunctionManager();
			totalmatches = 0;
			possiblematches = 0;
			emptybodymatches = 0;
			othersrcfuncs = 0;
			otherdestfuncs = 0;
			conflicts = 0;
			matchdiscovered = 0;
			mismatch = 0;
			mismatchList = new ArrayList<String>();
			mismatchCountDown = 100;
		}

		private static String getName(Function func) {
			String name = func.getName();
			int pos = name.indexOf("@@GLIB");
			if (pos >= 0) {
				name = name.substring(0, pos);
			}
			return name;
		}

		/**
		 * For every function in a manager, make sure a record exists in -mymap-
		 * @param funcMgr is the manager to iterate over
		 * @param mymap is the map to add records to
		 * @param isSrc is true if the srcexists field should be set to true, otherwise destexists is set
		 */
		private static void tagFunctionNames(FunctionManager funcMgr,Listing listing,
				TreeMap<String, MyFunction> mymap, boolean isSrc) {
			FunctionIterator functions = funcMgr.getFunctions(true);
			while (functions.hasNext()) {
				Function next = functions.next();
				if (next.isThunk()) continue;
				CodeUnit cu = listing.getCodeUnitAt(next.getEntryPoint());
				boolean hasbody = false;
				if ((cu != null) && (cu instanceof Instruction))
					hasbody = true;
				String funcName = getName(next);
				MyFunction myRec = mymap.get(funcName);
				if (myRec == null) {
					myRec = new MyFunction(funcName);
					mymap.put(myRec.name, myRec);
				}
				if (isSrc) {
					myRec.srcexists = true;
					myRec.srcbody = hasbody;
				}
				else {
					myRec.destexists = true;
					myRec.destbody = hasbody;
				}
			}
			// Make sure external functions have an entry
			functions = funcMgr.getExternalFunctions();
			while(functions.hasNext()) {
				Function next = functions.next();
				String funcName = getName(next);
				MyFunction myRec = mymap.get(funcName);
				if (myRec == null) {
					myRec = new MyFunction(funcName);
					mymap.put(myRec.name, myRec);
				}
				if (isSrc) {
					myRec.srcexists = true;
					myRec.srcbody = false;
				}
				else {
					myRec.destexists = true;
					myRec.destbody = false;
				}
			}
		}

		public void tag() {
			tagFunctionNames(sourceFuncMgr, sourceProg.getListing(), nameset, true);
			tagFunctionNames(destFuncMgr, destProg.getListing(), nameset, false);			
		}
		
		public void registerMatch(Address srcAddr,Address destAddr) {
			Function sourceFunc = sourceFuncMgr.getFunctionAt(srcAddr);
			if (sourceFunc == null) {
				return;
			}
			Function destFunc = destFuncMgr.getFunctionAt(destAddr);
			if (destFunc == null) {
				return;
			}
			totalmatches += 1;			// We have a match between functions

			String srcName = getName(sourceFunc);
			String destName = getName(destFunc);
			MyFunction srcRec = nameset.get(srcName);
			MyFunction destRec = nameset.get(destName);
			srcRec.srchits += 1;
			destRec.desthits += 1;
			if (srcRec == destRec) {
				srcRec.matched = true;
			}
			else {
				srcRec.mismatched = true;
				if (mismatchCountDown > 0) {
					mismatchList.add("Mismatch: " + srcName + " - " + destName);
					mismatchCountDown -= 1;
				}
			}
			
		}
		
		public void calcStats() {
			Iterator<MyFunction> iterator2 = nameset.values().iterator();
			while (iterator2.hasNext()) {
				MyFunction myfunc = iterator2.next();
				if (myfunc.srcexists && myfunc.destexists) {
					possiblematches += 1;
					if (!myfunc.srcbody || !myfunc.destbody)
						emptybodymatches += 1;			// One side or other does not have a body
				}
				else if (myfunc.srcexists) {
					othersrcfuncs += 1;
				}
				else if (myfunc.destexists) {
					otherdestfuncs += 1;
				}
				if (myfunc.mismatched)
					mismatch += 1;
				if (myfunc.matched) {
					if ((myfunc.srchits == 1) && (myfunc.desthits == 1)) {
						matchdiscovered += 1;
					}
					else {
						conflicts += 1;						// Match confused by conflicts
					}
				}
			}
			falsepositive = (double) mismatch / (double) possiblematches;		// Functions in source that were mismatched with dest
			falsenegative =
				(double) (possiblematches - matchdiscovered) / (double) possiblematches;			
		}
		
		public void reportResults(GhidraScript script,String msg) {
			script.println(msg);
			script.println("  False positive = " + Double.toString(falsepositive));
			script.println("  False negative = " + Double.toString(falsenegative));
			script.println("  Total reported matches = " + Integer.toString(totalmatches));
			script.println("  Possible valid matches = " + Integer.toString(possiblematches));
			script.println("  Empty body matches = " + Integer.toString(emptybodymatches));
			script.println("  Non-conflicting valid matches = " + Integer.toString(matchdiscovered));
			script.println("  Mismatches = " + Integer.toString(mismatch));
			script.println("  Conflicting valid matches = " + Integer.toString(conflicts));
			script.println("  Source unmatchable functions = " + Integer.toString(othersrcfuncs));
			script.println("  Destination unmatchable functions = " + Integer.toString(otherdestfuncs));			
		}
		
		public void reportFalseNegatives(GhidraScript script,boolean sourceSide,int max) {
			Iterator<MyFunction> iterator2 = nameset.values().iterator();
			int count = 0;
			while (iterator2.hasNext()) {
				MyFunction myfunc = iterator2.next();
				if ((!myfunc.srcexists)||(!myfunc.destexists)) continue;		// Make sure both sides have named function
				if ((!myfunc.srcbody)||(!myfunc.destbody)) continue;			// Make sure both sides have a body
				if (!myfunc.matched) {			// If the function pair was not matched
					if (sourceSide && (myfunc.srchits==0)) {
						script.println("Source miss: "+myfunc.name);
						count += 1;
					}
					else if ((!sourceSide)&&(myfunc.desthits==0)) {
						script.println("Dest miss: "+myfunc.name);
						count += 1;
					}
					if (count >= max) return;
				}
			}			
		}

		public void reportUnmatchable(GhidraScript script,boolean sourceSide,int max) {
			Iterator<MyFunction> iterator2 = nameset.values().iterator();
			int count = 0;
			while (iterator2.hasNext()) {
				MyFunction myfunc = iterator2.next();
				if (sourceSide) {
					if (myfunc.srcexists && !myfunc.destexists) {
						script.println("Source unmatchable: "+myfunc.name);
						count += 1;
					}
				}
				else {
					if (myfunc.destexists && !myfunc.srcexists) {
						script.println("Dest unmatchable: "+myfunc.name);
						count += 1;
					}
					if (count >= max) break;
				}
			}
		}

		public void reportMismatches(GhidraScript script) {
			for (String line : mismatchList) {
				script.println(line);
			}
		}
	}
	
	@Override
	protected void run() throws Exception {
		DomainFile vtFile = askDomainFile("Select VT Session");
		openVTSessionAndDoWork(vtFile);
	}

	private void openVTSessionAndDoWork(DomainFile domainFile) {

		DomainObject vtDomainObject = null;
		try {
			vtDomainObject = domainFile.getDomainObject(this, false, false, monitor);
			doWork((VTSessionDB) vtDomainObject);
		}
		catch (VersionException e) {
			e.printStackTrace();
		}
		catch (CancelledException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			if (vtDomainObject != null) {
				vtDomainObject.release(this);
			}
		}
	}

	private void doWork(VTSessionDB session) {
		println("Working on session: " + session);

		List<VTMatchSet> matchSets = session.getMatchSets();
		Iterator<VTMatchSet> iterator = matchSets.iterator();
		while (iterator.hasNext()) {
			evaluateMatchSet(iterator.next());
		}
		evaluateAccepted(session);
	}

	private void evaluateAccepted(VTSessionDB session) {
		VTScorer scorer = new VTScorer(session.getSourceProgram(),session.getDestinationProgram());
		scorer.tag();

		VTAssociationManager associationManager = session.getAssociationManager();
		List<VTAssociation> associations = associationManager.getAssociations();
		for (VTAssociation association : associations) {
			if (association.getStatus() == VTAssociationStatus.ACCEPTED) {
				Address srcAddr = association.getSourceAddress();
				Address destAddr = association.getDestinationAddress();
				scorer.registerMatch(srcAddr, destAddr);
			}
		}

		scorer.calcStats();
		scorer.reportResults(this,"OVERALL ACCEPTED RESULTS:");
//		scorer.reportFalseNegatives(this, true,20);
//		scorer.reportUnmatchable(this, true, 20);
		scorer.reportMismatches(this);
	}

	private void evaluateMatchSet(VTMatchSet matchset) {
		Collection<VTMatch> matches = matchset.getMatches();
		if (matches.isEmpty()) {
			println("Empty matchset - " + matchset.getProgramCorrelatorInfo().getName() + " (" +
				matchset.getID() + ")");
			return;
		}
		VTSession vtsession = matchset.getSession();
		VTScorer scorer = new VTScorer(vtsession.getSourceProgram(),vtsession.getDestinationProgram());
		scorer.tag();

		Iterator<VTMatch> iterator = matches.iterator();
		while (iterator.hasNext()) {
			VTMatch next = iterator.next();
			VTAssociation association = next.getAssociation();
			Address srcAddr = association.getSourceAddress();
			Address destAddr = association.getDestinationAddress();
			scorer.registerMatch(srcAddr, destAddr);
		}
		scorer.calcStats();
		scorer.reportResults(this,matchset.getProgramCorrelatorInfo().getName() + " (" + matchset.getID() +
			"):");
	}

}
