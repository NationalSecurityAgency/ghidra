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
#ifndef __PDB__ITERATE__H__
#define __PDB__ITERATE__H__

#include "pdb.h"
#include "symbol.h"
#include "print.h"
#include "xml.h"
#include "find.h"

void iterateDataTypes(PDBApiContext& ctx);
void iterateEnums(PDBApiContext& ctx);
void iterateTypedefs(PDBApiContext& ctx);
void iterateClasses(PDBApiContext& ctx);
void iterateFunctions(PDBApiContext& ctx);
void iterateTables(PDBApiContext& ctx, bool printAll);

#endif
