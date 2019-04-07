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
package ghidra.app.util.bin.format.elf;

/**
 * GNU Constants.
 */
public interface GnuConstants {

    //Versym symbol index values.

    /**Symbol is local.*/
    public final static short VER_NDX_LOCAL      =  0;
    /**Symbol is global.*/
    public final static short VER_NDX_GLOBAL     =  1;
    /**Beginning of reserved entries.*/
    public final static short VER_NDX_LORESERVE  = (short)0xff00;
    /**Symbol is to be eliminated.*/
    public final static short VER_NDX_ELIMINATE  = (short)0xff01;

}
