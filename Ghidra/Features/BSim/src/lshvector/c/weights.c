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
#include "executor/spi.h"
#include "utils/memutils.h"
#include <math.h>

#define LSH_IDFSIZE 512
#define LSH_TFSIZE 64
#define LSH_MAX_HASHENTRIES 1048576
#define LSH_MAX_K 31
#define LSH_MAX_L 1024
#define LSH_DEFAULT_K 17
#define LSH_DEFAULT_L 146

int32 lsh_k;			/* Number of bits in a binid */
int32 lsh_L;			/* Number of binnings */

static double lsh_idfweight[LSH_IDFSIZE]; /* Sorted weights least -> most probable for Inverse Document Freq */
static double lsh_tfweight[LSH_TFSIZE];	/* Sorted weights least -> most probable for Term Frequency */
static double lsh_weightnorm;	/* Normalization of idf weights over raw log(probability) */
static double lsh_probflip0;	/* Significance penalty for hash flips */
static double lsh_probflip1;
static double lsh_probdiff0;	/* Significance penalty for length differences */
static double lsh_probdiff1;
static double lsh_scale;	/* Final scaling for significance scoring */
static double lsh_addend;
static double lsh_probflip0_norm;
static double lsh_probflip1_norm;
static double lsh_probdiff0_norm;
static double lsh_probdiff1_norm;

typedef struct {
  uint32 hash;
  uint32 count;
} IDFEntry;

static MemoryContext lsh_mem_ctx;
static uint32 lsh_IDFTableMask;	/* mask for hash table computation */
static IDFEntry *lsh_IDFTable = NULL;	/* The IDFLookup table */
bool weights_loaded = false;

static void update_norms(void)

{
  int32 i;
  double scale_sqrt = sqrt(lsh_scale);
  lsh_probflip0_norm = lsh_probflip0 * lsh_scale;
  lsh_probflip1_norm = lsh_probflip1 * lsh_scale;
  lsh_probdiff0_norm = lsh_probdiff0 * lsh_scale;
  lsh_probdiff1_norm = lsh_probdiff1 * lsh_scale;
  lsh_weightnorm = lsh_weightnorm / lsh_scale;
  for(i=0;i<LSH_IDFSIZE;++i) {
    lsh_idfweight[i] *= scale_sqrt;
  }
}

/* 
 *  Load the IDF and TF weights and other scaling info from the table 'weighttable'
 *  If the table isn't present, return false
 *  This assumes the existence of a table with LSH_IDFSIZE + LSH_TFSIZE + 7 row constructed with
 *     CREATE TABLE weighttable (id integer,weight double precision);
 */
static bool load_weights_from_table(void)

{
  SPITupleTable *spi_tuptable;
  TupleDesc spi_tupdesc;
  uint64 i,proc;
  int32 ret;
  char *resstring;
  int32 resindex;
  double resweight;
  
  ret = SPI_connect();
  
  if (ret < 0)
    elog(ERROR,"lshvector load_weights_from_table: SPI_connect returned %d",ret);
  
  /* Check for the existence of weighttable */
  ret = SPI_execute("SELECT relname from pg_class where relname='weighttable';",true,0);
  proc = SPI_processed;
  if ((ret != SPI_OK_SELECT)||(proc != 1)) {
    elog(WARNING,"lshvector load_weights_from_table: weighttable not present - using default weights");
    SPI_finish();
    return false;
  }
    
  ret = SPI_execute("SELECT ALL * from weighttable;",true,0); /* Read(only) all rows from table */
  proc = SPI_processed;
  
  if ((ret != SPI_OK_SELECT)||(proc != (LSH_IDFSIZE+LSH_TFSIZE + 7))) {
    elog(WARNING,"lshvector load_weights_from_table: weighttable has incorrect length - reverting to default weights");
    SPI_finish();
    return false;
  }
  spi_tupdesc = SPI_tuptable->tupdesc;
  spi_tuptable = SPI_tuptable;
  
  for(i=0;i<proc;++i) {
    HeapTuple tuple = spi_tuptable->vals[i];
    resstring = SPI_getvalue(tuple, spi_tupdesc, 1); /* Column numbers start at 1 */
    resindex = strtol(resstring,NULL,10);
    pfree(resstring);
    resstring = SPI_getvalue(tuple, spi_tupdesc, 2);
    resweight = atof( resstring );
    pfree(resstring);
    if (resindex < LSH_IDFSIZE)
      lsh_idfweight[resindex] = resweight;
    else if (resindex < LSH_IDFSIZE + LSH_TFSIZE)
      lsh_tfweight[resindex - LSH_IDFSIZE] = resweight;
    else if (resindex == (LSH_IDFSIZE + LSH_TFSIZE))
      lsh_weightnorm = resweight;
    else if (resindex == (LSH_IDFSIZE + LSH_TFSIZE + 1))
      lsh_probflip0 = resweight;
    else if (resindex == (LSH_IDFSIZE + LSH_TFSIZE + 2))
      lsh_probflip1 = resweight;
    else if (resindex == (LSH_IDFSIZE + LSH_TFSIZE + 3))
      lsh_probdiff0 = resweight;
    else if (resindex == (LSH_IDFSIZE + LSH_TFSIZE + 4))
      lsh_probdiff1 = resweight;
    else if (resindex == (LSH_IDFSIZE + LSH_TFSIZE + 5))
      lsh_scale = resweight;
    else if (resindex == (LSH_IDFSIZE + LSH_TFSIZE + 6))
      lsh_addend = resweight;
    else {
      SPI_finish();
      return false;
    }
  }
  SPI_finish();
  update_norms();
  return true;
}

void lsh_load_weights(void)

{
  int32 i;
  if (load_weights_from_table()) /* Try to get weights from table */
    return;

  /* Provide some sort of reasonable default */
  for(i=0;i<LSH_IDFSIZE;++i)
    lsh_idfweight[i] = 1.0;
  for(i=0;i<LSH_TFSIZE;++i)
    lsh_tfweight[i] = 1.0;

  lsh_weightnorm = 13.0;
  lsh_probflip0 = 0.2;
  lsh_probflip1 = 20.0;
  lsh_probdiff0 = 0.2;
  lsh_probdiff1 = 20.0;
  lsh_scale = 1.0;
  lsh_addend = 0.0;
  update_norms();
}

static void initialize_idflookup_hashtable(uint32 size)

{
  uint32 i;
  MemoryContext oldctx;

  lsh_IDFTableMask = 1;
  while( lsh_IDFTableMask < size )
    lsh_IDFTableMask <<= 1;

  lsh_IDFTableMask <<= 1;
  oldctx = MemoryContextSwitchTo(lsh_mem_ctx);
  lsh_IDFTable = (IDFEntry *) palloc(sizeof(IDFEntry) * lsh_IDFTableMask);
  for(i=0;i<lsh_IDFTableMask;++i) {
    lsh_IDFTable[i].count = 0xffffffff;	/* Mark all the slots as empty */
  }

  lsh_IDFTableMask -= 1;
  MemoryContextSwitchTo(oldctx);
}

static void insert_idflookup_hash(uint32 hash,uint32 count)

{
  IDFEntry *ptr;
  uint32 val = hash & lsh_IDFTableMask;
  for(;;) {
    ptr = lsh_IDFTable + val;
    if (ptr->count == 0xffffffff) /* Found an empty slot */
      break;
    val = (val + 1) & lsh_IDFTableMask;
  }
  ptr->hash = hash;
  ptr->count = count;
}

static uint32 get_idflookup_count(uint32 hash)

{
  uint32 val;
  IDFEntry *ptr;
  if (lsh_IDFTableMask == 0)
    return 0;
  val = hash & lsh_IDFTableMask;
  for(;;) {
    ptr = lsh_IDFTable + val;
    if (ptr->count == 0xffffffff) break; /* Is slot empty */
    if (ptr->hash == hash)
      return ptr->count;
    val = (val + 1) & lsh_IDFTableMask;
  }
  return 0;			/* Entry is not in the table (assume 0 count) */
}

/*
 * Based on hash and existing idf and tf counts, calculate the final coefficient
 * Also calculate the vector length and hashcount
 */
void lsh_calc_weights(LSHVECTOR *vec)

{
  uint32 i;
  LSH_ITEM *ptr;
  uint32 idf;
  double length = 0.0;
  double coeff;
  uint32 tf;
  uint32 hashcount = 0;

  ptr = vec->items;
  for(i=0;i<vec->numitems;++i) {
    idf = get_idflookup_count(ptr[i].hash);
    ptr[i].idf = idf;
    tf = ptr[i].tf;
    coeff = lsh_idfweight[idf] * lsh_tfweight[ tf - 1 ];
    ptr[i].coeff = coeff;
    length += coeff * coeff;
    hashcount += tf;
  }
  vec->length = sqrt(length);
  vec->hashcount = hashcount;
}

/* Load the most common IDF hashes for lookup and weight generation from the table 'idflookup' 
 * If the table isn't present, return false
 * This assumes the existence of a table with (approximately) 1000 rows constructed with
 *     CREATE TABLE idflookup( hash bigint, lookup integer);
 */
static bool load_idflookup_from_table(void)

{
  SPITupleTable *spi_tuptable;
  TupleDesc spi_tupdesc;
  uint64 i,proc;
  int32 ret;
  char *resstring;
  uint32 rescount;
  uint32 reshash;

  ret = SPI_connect();

  if (ret < 0)
    elog(ERROR,"lshvector load_idflookup_from_table: SPI_connect returned %d",ret);

  /* Check for the existence of idflookup */
  ret = SPI_execute("SELECT relname from pg_class where relname='idflookup';",true,0);
  proc = SPI_processed;
  if ((ret != SPI_OK_SELECT)||(proc != 1)) {
    elog(WARNING,"lshvector load_idflookup_from_table: No IDF hashes present");
    SPI_finish();
    return false;
  }

  ret = SPI_execute("SELECT ALL * from idflookup;",true,0); /* Read(only) all rows from table */
  proc = SPI_processed;
  if ((ret != SPI_OK_SELECT)||(proc <= 1)||(proc > LSH_MAX_HASHENTRIES)) {
    elog(WARNING,"lshvector load_idflookup_from_table: idflookup has invalid size: IDF hashes not loaded");
    SPI_finish();
    return false;
  }
  initialize_idflookup_hashtable((uint32)proc);	/* Allocate the hashtable to hold entries for each row */
  
  spi_tupdesc = SPI_tuptable->tupdesc;
  spi_tuptable = SPI_tuptable;

  for(i=0;i<proc;++i) {
    HeapTuple tuple = spi_tuptable->vals[i];
    resstring = SPI_getvalue(tuple, spi_tupdesc, 1); /* Column numbers start at 1 */
    reshash = strtoul(resstring,NULL,10);
    pfree(resstring);
    resstring = SPI_getvalue(tuple, spi_tupdesc, 2);
    rescount = strtoul(resstring,NULL,10);
    pfree(resstring);
    insert_idflookup_hash(reshash,rescount);
  }
  SPI_finish();
  return true;
}

void lsh_load_binconfig(void)

{ /* Load the k and L parameters from the database */
  SPITupleTable *spi_tuptable;
  TupleDesc spi_tupdesc;
  uint64 proc;
  int32 ret;
  char *resstring;
  HeapTuple tuple;

  ret = SPI_connect();

  if (ret < 0)
    elog(ERROR,"lshvector lsh_load_binconfig: SPI_connect returned %d",ret);

  /* Check for the existence of keyvaluetable */
  ret = SPI_execute("SELECT relname from pg_class where relname='keyvaluetable';",true,0);
  proc = SPI_processed;
  if ((ret != SPI_OK_SELECT)||(proc != 1)) {
    SPI_finish();
    lsh_k = LSH_DEFAULT_K;		/* Reasonable defaults if configuration parameters don't exist */
    lsh_L = LSH_DEFAULT_L;
    return;
  }

  /* Get the 'k' value */
  ret = SPI_execute("SELECT value FROM keyvaluetable WHERE key='k';",true,0);
  proc = SPI_processed;
  if ((ret != SPI_OK_SELECT)||(proc != 1))
    elog(ERROR,"lshvector lsh_load_binconfig: Could not load 'k' value from keyvaluetable");

  spi_tupdesc = SPI_tuptable->tupdesc;
  spi_tuptable = SPI_tuptable;

  tuple = spi_tuptable->vals[0];
  resstring = SPI_getvalue(tuple,spi_tupdesc, 1); /* First column */
  lsh_k = strtoul(resstring,NULL,10);
  pfree(resstring);

  /* Get the 'L' value */
  ret = SPI_execute("SELECT value FROM keyvaluetable WHERE key='L';",true,0);
  proc = SPI_processed;
  if ((ret != SPI_OK_SELECT)||(proc != 1))
    elog(ERROR,"lshvector lsh_load_binconfig: Could not load 'L' value from keyvaluetable");

  spi_tupdesc = SPI_tuptable->tupdesc;
  spi_tuptable = SPI_tuptable;

  tuple = spi_tuptable->vals[0];
  resstring = SPI_getvalue(tuple,spi_tupdesc, 1); /* First column */
  lsh_L = strtoul(resstring,NULL,10);
  pfree(resstring);
  SPI_finish();

  if (lsh_k < 1 || lsh_k > LSH_MAX_K || lsh_L < 1 || lsh_L > LSH_MAX_L)
    elog(ERROR,"lshvector lsh_load_binconfig: Invalid k and L settings");
}

void lsh_load_lookuptable(void)

{
  if (lsh_IDFTable != NULL) {
    pfree(lsh_IDFTable);
    lsh_IDFTable = NULL;
  }

  if (load_idflookup_from_table())
    return;

  if (lsh_IDFTable != NULL) {
    pfree(lsh_IDFTable);
    lsh_IDFTable = NULL;
  }
  lsh_IDFTableMask = 0;	/* Default lookup, always return 0 */
}

/* Initialize the weight system, the first time the extension is loaded */
void lsh_initialize(void)

{
  lsh_mem_ctx = AllocSetContextCreate(TopMemoryContext,
				      "IDF weights lookup table",
				      ALLOCSET_DEFAULT_MINSIZE,
				      ALLOCSET_DEFAULT_INITSIZE,
				      ALLOCSET_DEFAULT_MAXSIZE);

  lsh_IDFTable = NULL;
  weights_loaded = false;

  lsh_setup_signtable();
}

double lsh_compare_internal(LSHVECTOR *a,LSHVECTOR *b,double *sig)

{
  double res = 0.0;
  double dotproduct;
  int32 intersectcount = 0;
  uint32 hash1,hash2;
  LSH_ITEM *aptr,*aend,*bptr,*bend;
  int32 t1,t2;
  double w1,w2;
  uint32 numflip,diff,min,max;

  aptr = a->items;
  aend = aptr + a->numitems;
  bptr = b->items;
  bend = bptr + b->numitems;
  
  if ((aptr != aend)&&(bptr != bend)) {
    hash1 = aptr->hash;
    hash2 = bptr->hash;
    for(;;) {
      if (hash1 == hash2) {
	t1 = aptr->tf;
	t2 = bptr->tf;
	if (t1 < t2) {		/* a has the smallest number of terms with same hash */
	  w1 = aptr->coeff;	/* Use a weight */
	  res += w1 * w1;
	  intersectcount += t1;	/* All of a terms are in the intersection, count them */
	}
	else {
	  w2 = bptr->coeff;	/* Use b weight */
	  res += w2 * w2;
	  intersectcount += t2;	/* All of b terms are in the intersection, count them */
	}
	aptr++;
	bptr++;
	if (aptr == aend) break;
	if (bptr == bend) break;
	hash1 = aptr->hash;
	hash2 = bptr->hash;
      }
      else if (hash1 < hash2) {
	aptr++;
	if (aptr == aend) break;
	hash1 = aptr->hash;
      }
      else {			/* hash1 > hash2 */
	bptr++;
	if (bptr == bend) break;
	hash2 = bptr->hash;
      }
    }
    dotproduct = res;
    res /= (a->length * b->length);
  }
  else
    dotproduct = res;

  if (a->hashcount < b->hashcount) {
    min = a->hashcount;		/* Smallest vector is a */
    max = b->hashcount;
  }
  else {
    min = b->hashcount;
    max = a->hashcount;
  }
  diff = max - min;		/* Subtract to get a positive difference */
  numflip = min - intersectcount;
  *sig = dotproduct - numflip * (lsh_probflip0_norm + lsh_probflip1_norm/max)
    - diff * (lsh_probdiff0_norm + lsh_probdiff1_norm/max) + lsh_addend;
  return res;
}

