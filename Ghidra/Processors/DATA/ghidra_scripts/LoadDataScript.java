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
//Loads the same file as binary using each of the DATA languages.
//Any DATA language can be used with any size file.
//The only issues are the POINTER sizes and does the file fit in the memory space.
//@category Processor.DATA

import ghidra.app.script.GhidraScript;
import ghidra.language.data.DataLanguageHelper;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.util.DefaultLanguageService;

import java.io.File;

public class LoadDataScript extends GhidraScript {

	@Override
	public void run( ) throws Exception {

		LanguageService languageService = DefaultLanguageService.getLanguageService( );

		LanguageCompilerSpecPair dataBE16 = DataLanguageHelper.getLanguage( languageService, 16, true );
		LanguageCompilerSpecPair dataBE32 = DataLanguageHelper.getLanguage( languageService, 32, true );
		LanguageCompilerSpecPair dataBE64 = DataLanguageHelper.getLanguage( languageService, 64, true );

		LanguageCompilerSpecPair dataLE16 = DataLanguageHelper.getLanguage( languageService, 16, false );
		LanguageCompilerSpecPair dataLE32 = DataLanguageHelper.getLanguage( languageService, 32, false );
		LanguageCompilerSpecPair dataLE64 = DataLanguageHelper.getLanguage( languageService, 64, false );

		File file = askFile( "Select DATA File", "OK" );
		if ( file == null ) {
			printerr( "No file selected, ending script." );
			return;
		}

		openProgram( importFileAsBinary( file, dataBE16.getLanguage( ), dataBE16.getCompilerSpec( ) ) );
		openProgram( importFileAsBinary( file, dataLE16.getLanguage( ), dataLE16.getCompilerSpec( ) ) );

		openProgram( importFileAsBinary( file, dataBE32.getLanguage( ), dataBE32.getCompilerSpec( ) ) );
		openProgram( importFileAsBinary( file, dataLE32.getLanguage( ), dataLE32.getCompilerSpec( ) ) );

		openProgram( importFileAsBinary( file, dataBE64.getLanguage( ), dataBE64.getCompilerSpec( ) ) );
		openProgram( importFileAsBinary( file, dataLE64.getLanguage( ), dataLE64.getCompilerSpec( ) ) );
	}

}
