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
// An example of how to use an existing Version Tracking session to iterate over accepted matches
// to manipulate function prototypes.
//@category Examples.Version Tracking

import ghidra.app.script.GhidraScript;
import ghidra.app.script.ImproperUseException;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.List;

public class OverrideFunctionPrototypesOnAcceptedMatchesScript extends GhidraScript {

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
		catch (ClassCastException e) {
			printerr("That domain object (" + domainFile.getName() + ") is not a VT session");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if (vtDomainObject != null) {
				vtDomainObject.release(this);
			}
		}
	}

	private void doWork(VTSessionDB session) throws InvalidInputException, DuplicateNameException,
			ImproperUseException {
		println("Working on session: " + session);

		Program sourceProg = session.getSourceProgram();
		Program destProg = session.getDestinationProgram();

		int transID = -1;
		boolean allIsGood = false;
		try {
			transID = destProg.startTransaction("OverrideFunctionPrototypes");

			Language sourceLanguage = sourceProg.getLanguage();
			Language destLanguage = destProg.getLanguage();

			LanguageDescription sourceDesc = sourceLanguage.getLanguageDescription();
			LanguageDescription destDesc = destLanguage.getLanguageDescription();

			if (!(sourceDesc.getProcessor().equals(destDesc.getProcessor()) &&
				sourceDesc.getEndian() == destDesc.getEndian() && sourceDesc.getSize() == destDesc.getSize())) {
				boolean yes =
					askYesNo("Warning: possibly incompatible source/dest architectures",
						"Source and destination programs might have different architectures. Continue?");
				if (!yes) {
					return;
				}
			}

			FunctionManager sourceFuncMgr = sourceProg.getFunctionManager();
			FunctionManager destFuncMgr = destProg.getFunctionManager();

			VTAssociationManager associationManager = session.getAssociationManager();
			List<VTAssociation> associations = associationManager.getAssociations();
			for (VTAssociation association : associations) {
				if (association.getType() == VTAssociationType.FUNCTION &&
					association.getStatus() == VTAssociationStatus.ACCEPTED) {

					Address srcAddr = association.getSourceAddress();
					Address destAddr = association.getDestinationAddress();
					Function sourceFunc = sourceFuncMgr.getFunctionAt(srcAddr);
					if (sourceFunc == null) {
						continue;
					}
					Function destFunc = destFuncMgr.getFunctionAt(destAddr);
					if (destFunc == null) {
						continue;
					}

					transfer(sourceFunc, destFunc);
				}
			}
			allIsGood = true;
		}
		finally {
			if (transID != -1) {
				destProg.endTransaction(transID, allIsGood);
			}
		}
	}

	@SuppressWarnings("deprecation")
	private void transfer(Function sourceFunc, Function destFunc) throws InvalidInputException,
			DuplicateNameException {

		// FIXME: this is just a skeleton, I am dumb, failed all of RE, etc.
		// please make this do what you really want

		destFunc.setReturnType(sourceFunc.getReturnType(), sourceFunc.getSignatureSource());
		destFunc.setName(sourceFunc.getName(), SourceType.USER_DEFINED);
		destFunc.setCallingConvention(sourceFunc.getCallingConventionName());
		int parameterCount = destFunc.getParameterCount();
		for (int ii = parameterCount - 1; ii >= 0; --ii) {
			// TODO: Fix deprecated method call
			destFunc.removeParameter(ii);
		}
		parameterCount = sourceFunc.getParameterCount();
		for (int ii = 0; ii < parameterCount; ++ii) {
			Parameter parameter = sourceFunc.getParameter(ii);
			// TODO: Fix deprecated method call
			destFunc.addParameter(parameter, SourceType.USER_DEFINED);
		}
	}
}
