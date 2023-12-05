

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION lshvector" to load this file. \quit

-- Create user-defined type for feature vector

CREATE FUNCTION lshvector_in(cstring)
RETURNS lshvector
AS 'MODULE_PATHNAME'
LANGUAGE C STABLE STRICT;
-- Stable because of configurable weights

CREATE FUNCTION lshvector_out(lshvector)
RETURNS cstring
AS 'MODULE_PATHNAME'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION lshvector_recv(internal)
RETURNS lshvector
AS 'MODULE_PATHNAME'
LANGUAGE C STABLE STRICT;
-- Stable because of configurable weights

CREATE FUNCTION lshvector_send(lshvector)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION lshvector_hash(lshvector)
RETURNS int8
AS 'MODULE_PATHNAME'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION lsh_load()
RETURNS int4
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION lsh_reload()
RETURNS int4
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION lsh_getweight(lshvector)
RETURNS float8
AS 'MODULE_PATHNAME'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE lshvector (
	INTERNALLENGTH = variable,
	INPUT = lshvector_in,
	OUTPUT = lshvector_out,
	RECEIVE = lshvector_recv,
	SEND = lshvector_send,
	ALIGNMENT = double,
	STORAGE = external
);

CREATE TYPE lshvector_comptype AS (
	sim DOUBLE PRECISION,
	sig DOUBLE PRECISION
);

CREATE FUNCTION lshvector_compare(lshvector,lshvector)
RETURNS lshvector_comptype
AS 'MODULE_PATHNAME'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION lshvector_overlap(lshvector,lshvector)
RETURNS bool
AS 'MODULE_PATHNAME'
LANGUAGE C STABLE STRICT;

CREATE FUNCTION lshvector_gin_extract_value(lshvector,internal)
RETURNS internal
AS 'MODULE_PATHNAME'
LANGUAGE C STABLE STRICT;

CREATE FUNCTION lshvector_gin_extract_query(lshvector,internal,int2,internal,internal,internal,internal)
RETURNS internal
AS 'MODULE_PATHNAME'
LANGUAGE C STABLE STRICT;

CREATE FUNCTION lshvector_gin_consistent(internal, int2, lshvector, int4, internal, internal, internal, internal)
RETURNS bool
AS 'MODULE_PATHNAME'
LANGUAGE C IMMUTABLE STRICT;

CREATE OPERATOR % (
        LEFTARG = lshvector,
        RIGHTARG = lshvector,
        PROCEDURE = lshvector_overlap,
        COMMUTATOR = '%',
        RESTRICT = contsel,
        JOIN = contjoinsel
);

CREATE OPERATOR CLASS gin_lshvector_ops
FOR TYPE lshvector USING gin
AS
        OPERATOR       1      % (lshvector,lshvector),
        FUNCTION       1      btint4cmp (int4,int4),
        FUNCTION       2      lshvector_gin_extract_value (lshvector,internal),
        FUNCTION       3      lshvector_gin_extract_query (lshvector,internal,int2,internal,internal,internal,internal),
	FUNCTION       4      lshvector_gin_consistent (internal,int2,lshvector,int4,internal,internal,internal,internal),
        STORAGE        int4;
