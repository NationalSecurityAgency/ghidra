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
#ifndef __LSH_H__
#define __LSH_H__

#include "postgres.h"

typedef struct
{
  uint32 hash;			/* A specific hash */
  uint16 tf;			/* Associated hash(term) frequency */
  uint16 idf;			/* Inverse Document Frequency */
  double coeff;			/* The actual weight of this hash as a coefficient */
} LSH_ITEM;

typedef struct
{
  int32 vl_len_;		/* varlena header (do not touch directly!) */
  uint32 numitems;
  uint32 hashcount;		/* Total number of hashes counting multiplicity */
  double length;		/* Length of vector */
  LSH_ITEM items[1];
} LSHVECTOR;

#define HDRSIZELSH           offsetof(LSHVECTOR,items)

#define DatumGetLshVectorP(X)    ((LSHVECTOR *) PG_DETOAST_DATUM(X))
#define PG_GETARG_LSHVECTOR_P(n) DatumGetLshVectorP(PG_GETARG_DATUM(n))

extern int32 lsh_k;
extern int32 lsh_L;
extern uint32 crc32tab[];
extern bool weights_loaded;

extern void lsh_calc_weights(LSHVECTOR *vec);
extern void lsh_initialize(void);
extern void lsh_load_weights(void);
extern void lsh_load_lookuptable(void);
extern uint64 lsh_hash_internal(LSHVECTOR *vec);
extern double lsh_compare_internal(LSHVECTOR *a,LSHVECTOR *b,double *sig);

extern void lsh_setup_signtable(void);
extern void lsh_load_binconfig(void);
extern void lsh_generate_binids(uint32 *res,LSH_ITEM *vec,uint32 vecsize);
extern void lsh_generate_binids_datum(Datum *res,LSH_ITEM *vec,uint32 vecsize);

#endif
