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
package ghidra.macosx;

import ghidra.app.util.bin.format.macho.CpuSubTypes;
import ghidra.app.util.bin.format.macho.CpuTypes;
import ghidra.program.model.lang.*;

import java.io.IOException;
import java.util.List;

public final class MacosxLanguageHelper {

	/**
	 * Returns the language/compiler specification pair for the given CPU type and CPU sub-type.
	 * @param languageService the language service
	 * @param cpuType the CPU type
	 * @param cpuSubType the CPU sub-type
	 * @return the language and compiler specification pair for the given CPU type and CPU sub-type.
	 * @throws IOException if the language cannot be located
	 */
	public static LanguageCompilerSpecPair getLanguageCompilerSpecPair(LanguageService languageService, int cpuType, int cpuSubType) throws IOException {
	    Processor ARM     = Processor.findOrPossiblyCreateProcessor( "ARM" );
	    Processor ARM64   = Processor.findOrPossiblyCreateProcessor( "AARCH64" );
        Processor x86     = Processor.findOrPossiblyCreateProcessor( "x86" );
        Processor PowerPC = Processor.findOrPossiblyCreateProcessor( "PowerPC" );

        Processor processor = null;
        Endian endian = null;
        Integer size = null;
        String variant = "default";
        CompilerSpecID compilerSpecID = new CompilerSpecID( "default" );

        if ( cpuType == CpuTypes.CPU_TYPE_ARM ) {
            processor = ARM;
            endian = Endian.LITTLE;
            if ( cpuSubType == CpuSubTypes.CPU_SUBTYPE_ARM_V6 ) {
                variant = "v6";
            }
            else if ( cpuSubType == CpuSubTypes.CPU_SUBTYPE_ARM_V7  ||
            		  cpuSubType == CpuSubTypes.CPU_SUBTYPE_ARM_V7F ||
            		  cpuSubType == CpuSubTypes.CPU_SUBTYPE_ARM_V7S ||
            		  cpuSubType == CpuSubTypes.CPU_SUBTYPE_ARM_V7K ||
            		  cpuSubType == CpuSubTypes.CPU_SUBTYPE_ARM_ALL ) {
                variant = "v7";
            }
        }
        else if ( cpuType == CpuTypes.CPU_TYPE_X86 || 
        		  cpuType == CpuTypes.CPU_TYPE_X86_64 ) {
            processor = x86;
            endian = Endian.LITTLE;
            size = cpuType == CpuTypes.CPU_TYPE_X86_64 ? 64 : 32;
            compilerSpecID = new CompilerSpecID( "gcc" );
        }
        else if ( cpuType == CpuTypes.CPU_TYPE_POWERPC || 
        		  cpuType == CpuTypes.CPU_TYPE_POWERPC64 ) {
            processor = PowerPC;
            endian = Endian.BIG;
            size = cpuType == CpuTypes.CPU_TYPE_POWERPC64 ? 64 : 32;
            compilerSpecID = new CompilerSpecID( "macosx" );
        }
        else if ( cpuType == CpuTypes.CPU_TYPE_ARM_64) {
          processor = ARM64;
          endian = Endian.LITTLE;
          size = 64;
          variant = "v8A";
      }

        LanguageCompilerSpecQuery query = new LanguageCompilerSpecQuery( processor, endian, size, variant, compilerSpecID );

        List<LanguageCompilerSpecPair> pairs = languageService.getLanguageCompilerSpecPairs( query );

        if ( pairs.size() > 0 ) {
            if ( pairs.size() > 1 ) {
                throw new LanguageNotFoundException( "Too many languages for " + Integer.toHexString( cpuType ) + "." + Integer.toHexString( cpuSubType ) );
            }
            LanguageCompilerSpecPair pair = pairs.get( 0 );
            return new LanguageCompilerSpecPair( pair.languageID, pair.compilerSpecID );
        }

        throw new LanguageNotFoundException("Unable to locate language for " + Integer.toHexString( cpuType ) + "." + Integer.toHexString( cpuSubType ) );
    }
}
