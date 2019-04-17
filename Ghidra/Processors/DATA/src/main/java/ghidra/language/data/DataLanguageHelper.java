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
package ghidra.language.data;

import ghidra.program.model.lang.*;

import java.util.List;

public final class DataLanguageHelper {

	public final static LanguageCompilerSpecPair getLanguage( LanguageService languageService, int pointerSize, boolean isBigEndian ) throws LanguageNotFoundException {
		if ( pointerSize != 16 && pointerSize != 32 && pointerSize != 64 ) {
			throw new LanguageNotFoundException("Unable to locate DATA language for pointer size:" + pointerSize );
		}
	    Processor processor = Processor.findOrPossiblyCreateProcessor( "DATA" );
        Endian endian = isBigEndian ? Endian.BIG : Endian.LITTLE;
        int size = 64;
        String variant = "default";
        CompilerSpecID compilerSpecID = new CompilerSpecID( "pointer" + pointerSize );

		LanguageCompilerSpecQuery query = new LanguageCompilerSpecQuery( processor, endian, size, variant, compilerSpecID );

        List<LanguageCompilerSpecPair> pairs = languageService.getLanguageCompilerSpecPairs( query );

        if ( pairs.size() > 0 ) {
            if ( pairs.size() > 1 ) {
                throw new LanguageNotFoundException( "Too many DATA languages" );
            }
            LanguageCompilerSpecPair pair = pairs.get( 0 );
            return new LanguageCompilerSpecPair( pair.languageID, pair.compilerSpecID );
        }

        throw new LanguageNotFoundException("Unable to locate DATA language" );
	}
}
