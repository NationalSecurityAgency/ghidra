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
//Loads the contents of another program
//into the current program.
//The languages of the two programs must match!
//The information from the source program takes priority
//over the destination program. Meaning, all information in
//the destination program will be removed to make
//room for the information coming from the source
//program.
//@category Program

import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;


public class MergeTwoProgramsScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		if ( currentProgram == null ) {
			printerr( "Please open a program first!" );
			return;
		}

		Program otherProgram = askProgram( "Select program from which to merge: " );

		if ( otherProgram == null ) {
			printerr( "Please select the other program first!" );
			return;
		}

		if ( !currentProgram.getLanguage().equals( otherProgram.getLanguage() ) ) {
			printerr( "Incompatible program languages!" );
			return;
		}

		if ( currentProgram.getMemory().intersects( otherProgram.getMemory() ) ) {
			printerr( "Memory map of current program must be disjoint from other program!" );
			return;
		}

		openProgram( currentProgram );

		mergeMemory      ( currentProgram, otherProgram );
		mergeSymbols     ( currentProgram, otherProgram );
		mergeBookmarks   ( currentProgram, otherProgram );
		mergeComments    ( currentProgram, otherProgram );
		mergeData        ( currentProgram, otherProgram );
		mergeInstructions( currentProgram, otherProgram );
		mergeEquates     ( currentProgram, otherProgram );
		mergeReferences  ( currentProgram, otherProgram );
	}

	private void mergeReferences( Program currProgram, Program otherProgram ) {
		monitor.setMessage( "Merging references..." );
		ReferenceManager currentReferenceManager = currProgram.getReferenceManager();
		ReferenceManager otherReferenceManager = otherProgram.getReferenceManager();
		ReferenceIterator otherReferenceIterator = otherReferenceManager.getReferenceIterator( otherProgram.getMinAddress() );
		while ( otherReferenceIterator.hasNext() ) {
			if ( monitor.isCancelled() ) {
				break;
			}
			Reference otherReference = otherReferenceIterator.next();
			if ( otherReference.isStackReference() ) {
				continue;
			}
			currentReferenceManager.addReference( otherReference );
		}
	}

	private void mergeInstructions( Program currProgram, Program otherProgram ) {
		monitor.setMessage( "Merging instructions..." );
		Listing currentListing = currProgram.getListing();
		Listing otherListing = otherProgram.getListing();
		InstructionIterator otherInstructions = otherListing.getInstructions( true );
		while ( otherInstructions.hasNext() ) {
			if ( monitor.isCancelled() ) {
				break;
			}
			Instruction otherInstruction = otherInstructions.next();
			if ( currentListing.isUndefined( otherInstruction.getMinAddress(), otherInstruction.getMaxAddress() ) ) {
				disassemble( otherInstruction.getMinAddress() );
			}
		}
	}

	private void mergeEquates( Program currProgram, Program otherProgram ) throws Exception {
		monitor.setMessage( "Merging equates..." );
		EquateTable currentEquateTable = currProgram.getEquateTable();
		EquateTable otherEquateTable = otherProgram.getEquateTable();
		Iterator<Equate> otherEquates = otherEquateTable.getEquates();
		while ( otherEquates.hasNext() ) {
			if ( monitor.isCancelled() ) {
				break;
			}
			Equate otherEquate = otherEquates.next();
			Equate currentEquate = currentEquateTable.createEquate( otherEquate.getName(), otherEquate.getValue() );
			EquateReference [] otherEquateReferences = otherEquate.getReferences();
			for ( EquateReference otherEquateReference : otherEquateReferences ) {
				if ( monitor.isCancelled() ) {
					break;
				}
				currentEquate.addReference( otherEquateReference.getAddress(), otherEquateReference.getOpIndex() );
			}
		}
	}

	private void mergeData( Program currProgram, Program otherProgram ) throws Exception {
		monitor.setMessage( "Merging data..." );
		Listing currentListing = currProgram.getListing();
		Listing otherListing = otherProgram.getListing();
		DataIterator otherDataIterator = otherListing.getDefinedData( true );
		while ( otherDataIterator.hasNext() ) {
			if ( monitor.isCancelled() ) {
				break;
			}
			Data otherData = otherDataIterator.next();
			if ( currentListing.isUndefined( otherData.getMinAddress(), otherData.getMaxAddress() ) ) {
				currentListing.createData( otherData.getMinAddress(), otherData.getDataType() );
			}
		}
	}

	private void mergeComments( Program currProgram, Program otherProgram ) throws Exception {
		monitor.setMessage( "Merging comments..." );
		int [] commentTypes = {
			CodeUnit.EOL_COMMENT,
			CodeUnit.PRE_COMMENT,
			CodeUnit.POST_COMMENT,
			CodeUnit.PLATE_COMMENT,
			CodeUnit.REPEATABLE_COMMENT,
		};
		Listing currentListing = currProgram.getListing();
		Listing otherListing = otherProgram.getListing();
		CodeUnitIterator otherCodeUnits = otherListing.getCodeUnits( true );
		while ( otherCodeUnits.hasNext() ) {
			if ( monitor.isCancelled() ) {
				break;
			}
			CodeUnit otherCodeUnit = otherCodeUnits.next();
			for ( int commentType : commentTypes ) {
				if ( monitor.isCancelled() ) {
					break;
				}
				String otherComment = otherCodeUnit.getComment( commentType );
				if ( otherComment != null ) {
					currentListing.setComment( otherCodeUnit.getAddress(), commentType, otherComment );
				}
			}
		}
	}

	private void mergeBookmarks( Program currProgram, Program otherProgram ) {
		monitor.setMessage( "Merging bookmarks..." );
		BookmarkManager currentBookmarkManager = currProgram.getBookmarkManager();
		BookmarkManager otherBookmarkManager = otherProgram.getBookmarkManager();
		Iterator<Bookmark> otherBookmarks = otherBookmarkManager.getBookmarksIterator();
		while ( otherBookmarks.hasNext() ) {
			if ( monitor.isCancelled() ) {
				break;
			}
			Bookmark otherBookmark = otherBookmarks.next();
			currentBookmarkManager.setBookmark( otherBookmark.getAddress(),
				otherBookmark.getTypeString(),
				otherBookmark.getCategory(),
				otherBookmark.getComment() );
		}
	}

	private void mergeSymbols( Program currProgram, Program otherProgram ) throws Exception {
		monitor.setMessage( "Merging symbols..." );
		SymbolTable currentSymbolTable = currProgram.getSymbolTable();
		SymbolTable otherSymbolTable = otherProgram.getSymbolTable();
		SymbolIterator otherSymbols = otherSymbolTable.getAllSymbols( false );
		while ( otherSymbols.hasNext() ) {
			if ( monitor.isCancelled() ) {
				break;
			}
			Symbol otherSymbol = otherSymbols.next();
			if ( otherSymbol.isDynamic() ) {
				continue;
			}
			try {
				Namespace otherNamespace = otherSymbol.getParentNamespace();
				Namespace currentNamespace = mirrorNamespace( currProgram, otherProgram, otherNamespace );
				if ( otherSymbol.getSymbolType() == SymbolType.FUNCTION ) {
					Function otherFunction = otherProgram.getListing().getFunctionAt( otherSymbol.getAddress() );
					currProgram.getListing().createFunction( otherSymbol.getName(),
						currentNamespace,
						otherFunction.getEntryPoint(),
						otherFunction.getBody(),
						SourceType.USER_DEFINED );
				}
				else {
					currentSymbolTable.createLabel( otherSymbol.getAddress(),
						otherSymbol.getName(),
						currentNamespace,
						SourceType.USER_DEFINED );
				}
			}
			catch ( Exception e ) {
				printerr( "Unable to create symbol: " + otherSymbol.getName() );
			}
		}
	}

	private Namespace mirrorNamespace( Program currProgram, Program otherProgram, Namespace otherNamespace ) throws Exception {
		if ( otherNamespace == null ) {
			return currProgram.getGlobalNamespace();
		}
		SourceType source = SourceType.USER_DEFINED;//this will be default, since we are running a script!
		try {
			source = otherNamespace.getSymbol().getSource();
		}
		catch ( Exception e ) {
		}
		return NamespaceUtils.createNamespaceHierarchy(otherNamespace.getName(true), null,
			currProgram, source);
	}

	private void mergeMemory( Program currProgram, Program otherProgram ) throws Exception {
		monitor.setMessage( "Merging memory..." );
		Memory otherMemory = otherProgram.getMemory();
		MemoryBlock[] otherBlocks = otherMemory.getBlocks();
		MessageLog log = new MessageLog();
		for (MemoryBlock otherBlock : otherBlocks) {
			if (monitor.isCancelled()) {
				break;
			}
			if (otherBlock.getType() != MemoryBlockType.DEFAULT) {
				printerr("Unhandled memory block type: " + otherBlock.getName());
				continue;
			}
			if (otherBlock.isInitialized()) {
				MemoryBlockUtils.createInitializedBlock(currProgram, false, otherBlock.getName(),
					otherBlock.getStart(), otherBlock.getData(), otherBlock.getSize(),
					otherBlock.getComment(), otherBlock.getSourceName(), otherBlock.isRead(),
					otherBlock.isWrite(), otherBlock.isExecute(), log, monitor);
			}
			else {
				MemoryBlockUtils.createUninitializedBlock(currProgram, false, otherBlock.getName(),
					otherBlock.getStart(), otherBlock.getSize(), otherBlock.getComment(),
					otherBlock.getSourceName(), otherBlock.isRead(), otherBlock.isWrite(),
					otherBlock.isExecute(), log);
			}
		}
	}

}
