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
#include "lsh.h"
#include "fmgr.h"
#include "funcapi.h"
#include "access/htup_details.h"
#include "access/gin.h"
#include "libpq/pqformat.h"
#include <ctype.h>

PG_MODULE_MAGIC;

void _PG_init(void);

PG_FUNCTION_INFO_V1(lshvector_in);
PG_FUNCTION_INFO_V1(lshvector_out);
PG_FUNCTION_INFO_V1(lshvector_send);
PG_FUNCTION_INFO_V1(lshvector_recv);
PG_FUNCTION_INFO_V1(lshvector_hash);
PG_FUNCTION_INFO_V1(lshvector_compare);
PG_FUNCTION_INFO_V1(lshvector_overlap);

PG_FUNCTION_INFO_V1(lshvector_gin_extract_value);
PG_FUNCTION_INFO_V1(lshvector_gin_extract_query);
PG_FUNCTION_INFO_V1(lshvector_gin_consistent);

PG_FUNCTION_INFO_V1(lsh_load);
PG_FUNCTION_INFO_V1(lsh_reload);
PG_FUNCTION_INFO_V1(lsh_getweight);

Datum lshvector_in(PG_FUNCTION_ARGS);
Datum lshvector_out(PG_FUNCTION_ARGS);
Datum lshvector_send(PG_FUNCTION_ARGS);
Datum lshvector_recv(PG_FUNCTION_ARGS);
Datum lshvector_hash(PG_FUNCTION_ARGS);
Datum lshvector_compare(PG_FUNCTION_ARGS);
Datum lshvector_overlap(PG_FUNCTION_ARGS);

Datum lshvector_gin_extract_value(PG_FUNCTION_ARGS);
Datum lshvector_gin_extract_query(PG_FUNCTION_ARGS);
Datum lshvector_gin_consistent(PG_FUNCTION_ARGS);

Datum lsh_load(PG_FUNCTION_ARGS);
Datum lsh_reload(PG_FUNCTION_ARGS);
Datum lsh_getweight(PG_FUNCTION_ARGS);

/*
 * Allocate memory for an LSHVECTOR given the raw count of the number of hash entries in the vector
 */
static LSHVECTOR *allocate_lshvector(uint32 numentries)

{
  LSHVECTOR *out;
  uint32 maxitems, commonlen;

  /* Maximum number of hashes in a single LSHVECTOR assuming a 1 gigabyte allocation limit */
  maxitems =  (0x3fffffff - HDRSIZELSH) / sizeof(LSH_ITEM);

  if (numentries > maxitems) {
    ereport(ERROR,(errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),errmsg("Exceeded maximum entries for single lshvector")));
    /* Does not return */
  }
  commonlen = HDRSIZELSH + numentries * sizeof(LSH_ITEM);
  out = (LSHVECTOR *) palloc(commonlen);
  SET_VARSIZE(out,commonlen);
  return out;
}

void _PG_init(void)

{
  lsh_initialize();
}

Datum lsh_load(PG_FUNCTION_ARGS)

{
  if (!weights_loaded) {
    lsh_load_weights();
    lsh_load_lookuptable();
    lsh_load_binconfig();
    weights_loaded = true;
  }
  PG_RETURN_INT32(0);
}

Datum lsh_reload(PG_FUNCTION_ARGS)

{
  lsh_load_weights();
  lsh_load_lookuptable();
  lsh_load_binconfig();
  weights_loaded = true;
  PG_RETURN_INT32(0);
}

Datum lsh_getweight(PG_FUNCTION_ARGS)

{
  LSHVECTOR *vec = PG_GETARG_LSHVECTOR_P(0);
  uint32 arg = PG_GETARG_UINT32(1);
  double res;

  if (arg >= vec->numitems)
    res = 0.0;
  else
    res = vec->items[arg].coeff;
  PG_FREE_IF_COPY(vec,0);
  PG_RETURN_FLOAT8( res );
}

/*
 * text input
 */
Datum
lshvector_in(PG_FUNCTION_ARGS)
{
  char *buf = (char *) PG_GETARG_POINTER(0);
  char *ptr,*ptrstart;
  LSHVECTOR *vec;
  uint32 numitems = 0;
  uint32 commacount = 0;
  uint32 i,j;
  int32 val;
  char curc;
  
  ptr = buf;
  curc = '\0';
  while(*ptr) {
    curc = *ptr;
    if (isspace(curc)==0) break;
    ++ptr;
  }
  if (curc != '(')
    ereport(ERROR,(errcode(ERRCODE_SYNTAX_ERROR),errmsg("Missing opening '('"))); /* Does not return */
  ++ptr;
  ptrstart = ptr;
  while (*ptr) {
    curc = *ptr;
    if (curc == ':')
      numitems += 1;
    else if (curc == ',')
      commacount += 1;
    else if (curc == ')')
      break;
    ++ptr;
  }
  if ((curc != ')')||(numitems != commacount+1))
    ereport(ERROR,(errcode(ERRCODE_SYNTAX_ERROR),errmsg("Bad delimiters"))); /* Does not return */

  vec = allocate_lshvector(numitems);

  ptr = ptrstart;
  i = 0;
  j = 0;
  while(*ptr) {
    val = strtol(ptr,&ptr,16);
    if (j==0) {
      if ((val<1)||(val>64)) {
	pfree(vec);
	ereport(ERROR,(errcode(ERRCODE_SYNTAX_ERROR),errmsg("Term frequency count out of bounds"))); /* Does not return */
      }
      vec->items[i].tf = (uint16)val;
      j = 1;
    }
    else {
      vec->items[i].hash = (uint32)val;
      vec->items[i].idf = 0;
      j = 0;
      i += 1;
    }
    while(isspace( *ptr ))
      ptr++;
    if (*ptr == ')') break;
    if (*ptr == ':') {
      if (j==0) {
	pfree(vec);
	ereport(ERROR,(errcode(ERRCODE_SYNTAX_ERROR),errmsg("Expected ','"))); /* Does not return */
      }
      ptr++;
    }
    else if (*ptr == ',') {
      if (j==1) {
	pfree(vec);
	ereport(ERROR,(errcode(ERRCODE_SYNTAX_ERROR),errmsg("Expected ':'"))); /* Does not return */
      }
      ptr++;
    }
  }
  vec->numitems = numitems;
  lsh_calc_weights(vec);
  PG_RETURN_POINTER(vec);
}

/*
 * text output
 */
Datum
lshvector_out(PG_FUNCTION_ARGS)
{
  LSHVECTOR *vec = PG_GETARG_LSHVECTOR_P(0);
  StringInfoData buf;
  uint32 i,sz;

  initStringInfo(&buf);

  appendStringInfoChar(&buf,'(');
  sz = vec->numitems;
  for(i=0;i<sz;++i) {
    appendStringInfo(&buf,"%x",(int32)vec->items[i].tf);
    appendStringInfoChar(&buf,':');
    appendStringInfo(&buf,"%x",(int32)vec->items[i].hash);
    if (i+1 < sz)
      appendStringInfoChar(&buf,',');
  }
  appendStringInfoChar(&buf,')');

  PG_FREE_IF_COPY(vec,0);
  
  PG_RETURN_CSTRING(buf.data);
}

/*
 * binary output
 */
Datum
lshvector_send(PG_FUNCTION_ARGS)
{
  LSHVECTOR *vec = PG_GETARG_LSHVECTOR_P(0);
  uint32 i;
  uint32 numitems;
  StringInfoData buf;

  numitems = vec->numitems;
  
  pq_begintypsend(&buf);
  pq_sendint(&buf,numitems,4);

  for(i=0;i<numitems;++i) {
    pq_sendint(&buf,vec->items[i].tf,1);
    pq_sendint(&buf,vec->items[i].hash,4);
  }
  PG_FREE_IF_COPY(vec,0);
  PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

/*
 * binary input
 */
Datum
lshvector_recv(PG_FUNCTION_ARGS)
{
  LSHVECTOR *out;
  StringInfo buf = (StringInfo) PG_GETARG_POINTER(0);
  uint32 numitems;
  uint32 tf;
  uint32 i;

  numitems = pq_getmsgint(buf,4);
  out = allocate_lshvector(numitems);

  out->numitems = numitems;
  for(i=0;i<numitems;++i) {
    tf = pq_getmsgint(buf,1);
    if ((tf<1)||(tf>64)) {
      pfree(out);
      ereport(ERROR,(errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),errmsg("Term frequency is out of range")));
      /* Does not return */
    }
    out->items[i].tf = tf;
    out->items[i].hash = pq_getmsgint(buf,4);
  }
  lsh_calc_weights(out);
  PG_RETURN_POINTER(out);
}

Datum lshvector_hash(PG_FUNCTION_ARGS)
{
  LSHVECTOR *a = PG_GETARG_LSHVECTOR_P(0);
  int64 res = (int64)lsh_hash_internal(a);

  PG_FREE_IF_COPY(a,0);

  PG_RETURN_INT64(res);
}

Datum lshvector_compare(PG_FUNCTION_ARGS)
{
  LSHVECTOR *a = PG_GETARG_LSHVECTOR_P(0);
  LSHVECTOR *b = PG_GETARG_LSHVECTOR_P(1);
  TupleDesc tupdesc;
  TupleDesc bless;
  HeapTuple restuple;
  Datum dvalues[2];
  bool nulls[2] = {false, false};
  double sim,sig;

  sim = lsh_compare_internal(a,b,&sig);
  PG_FREE_IF_COPY(a,0);
  PG_FREE_IF_COPY(b,1);

  if (get_call_result_type(fcinfo,NULL,&tupdesc) != TYPEFUNC_COMPOSITE)
    elog(ERROR,"Could not get composite row type to return");

  bless = BlessTupleDesc(tupdesc);
  
  dvalues[0] = Float8GetDatum(sim);
  dvalues[1] = Float8GetDatum(sig);
  restuple = heap_form_tuple(bless,dvalues,nulls);
  return HeapTupleGetDatum(restuple);
}

/*
 * This is the actual operator function being accelerated by the gin index.  In truth, the index itself
 * defines the operator, so the commented out code below emulates the indexes key generation process and
 * looks for overlap in the keys between two vectors.  In practice, any query that invokes this operator
 * will hopefully be going through the index and so doesn't need to evaluate this function.  For
 * cases where postgresql does a recheck after going through the index, there is no query that doesn't send
 * the results of the operator test to a similarity filter.  So there is no reason to actually perform
 * the overlap test.  So we just implement a NOP return that always returns true.
 */
Datum lshvector_overlap(PG_FUNCTION_ARGS)
{
/*   bool res; */
/*   int32 i; */
/*   LSHVECTOR *a = PG_GETARG_LSHVECTOR_P(0); */
/*   LSHVECTOR *b = PG_GETARG_LSHVECTOR_P(1); */
/*   uint32 *bina = (uint32 *)palloc( sizeof(uint32) * lsh_L ); */
/*   uint32 *binb = (uint32 *)palloc( sizeof(uint32) * lsh_L ); */

/*   lsh_generate_binids(bina,a->items,a->numitems); */
/*   lsh_generate_binids(binb,b->items,b->numitems); */
/*   PG_FREE_IF_COPY(a,0); */
/*   PG_FREE_IF_COPY(b,1); */

/*   res = false;			/\* Assume no overlap *\/ */
/*   for(i=0;i<lsh_L;++i) { */
/*     if (bina[i] == binb[i]) { */
/*       res = true;		/\* We found an overlap, (only need one) *\/ */
/*       break; */
/*     } */
/*   } */
/*   pfree(bina); */
/*   pfree(binb); */

    
  PG_RETURN_BOOL(true);
}

Datum lshvector_gin_extract_value(PG_FUNCTION_ARGS)

{
  LSHVECTOR *a = PG_GETARG_LSHVECTOR_P(0);
  int32 *nkeys = (int32 *) PG_GETARG_POINTER(1);
  Datum *entries = (Datum *)palloc( sizeof(Datum) * lsh_L );
  
  lsh_generate_binids_datum(entries,a->items,a->numitems);
  PG_FREE_IF_COPY(a,0);
  *nkeys = lsh_L;
  PG_RETURN_POINTER(entries);
}

Datum lshvector_gin_extract_query(PG_FUNCTION_ARGS)

{
  LSHVECTOR *a = PG_GETARG_LSHVECTOR_P(0);
  int32	*nkeys = (int32 *) PG_GETARG_POINTER(1);
        /* StrategyNumber strategy = PG_GETARG_UINT16(2); */
	/* bool   **pmatch = (bool **) PG_GETARG_POINTER(3); */
        /* Pointer **extra_data = (Pointer **) PG_GETARG_POINTER(4); */
	/* bool   **nullFlags = (bool **) PG_GETARG_POINTER(5); */
        /* int32 *searchMode = (int32 *) PG_GETARG_POINTER(6); */
  Datum *entries = (Datum *)palloc( sizeof(Datum) * lsh_L );
  
  lsh_generate_binids_datum(entries,a->items,a->numitems);
  PG_FREE_IF_COPY(a,0);
  *nkeys = lsh_L;
  PG_RETURN_POINTER(entries);
}

Datum lshvector_gin_consistent(PG_FUNCTION_ARGS)

{
  bool *check = (bool *) PG_GETARG_POINTER(0);
         /* StrategyNumber strategy = PG_GETARG_UINT16(1); */
         /* LSHVECTOR *a = PG_GETARG_LSHVECTOR_P(2); */
  int32	nkeys = PG_GETARG_INT32(3);
         /* Pointer *extra_data = (Pointer *) PG_GETARG_POINTER(4); */
  bool *recheck = (bool *) PG_GETARG_POINTER(5);
  bool res = false;
  int32 i;
  
  *recheck = false;		/* The operator does NOT need to be recalculated, this routine should exactly match */
  for(i=0;i<nkeys;++i) {
    if (check[i]) {		/* If ANY hash is present in the indexed lshvector */
      res = true;		/* this is considered an overlap */
      break;			/* and we don't need to look any further */
    }
  }
  PG_RETURN_BOOL(res);
}
