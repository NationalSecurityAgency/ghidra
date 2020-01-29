<?xml version='1.0'?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:param name="generate.toc">
  article/appendix  nop
  article   title
  book      title,example,equation
  chapter   nop
  part      toc,title
  preface   toc,title
  qandadiv  toc
  qandaset  toc
  reference toc,title
  sect1     nop
  sect2     nop
  sect3     nop
  sect4     nop
  sect5     nop
  section   nop
  set       toc,title
</xsl:param>

<!-- Turn off automatic table numbering, adjust xref labeling -->
<xsl:param name="local.l10n.xml" select="document('')"/>
<l:i18n xmlns:l="http://docbook.sourceforge.net/xmlns/l10n/1.0">
  <l:l10n language="en">
    <l:context name="title">
      <l:teamplate name="table" text="%t"/>
    </l:context>
    <l:context name="xref-number-and-title">
      <l:template name="table" text="the table titled &#8220;%t&#8221;"/>
    </l:context>
    <l:context name="xref">
      <l:template name="sect1" text="“%t”"/>
       <l:template name="sect2" text="“%t”"/>
       <l:template name="sect3" text="“%t”"/>
       <l:template name="sect4" text="“%t”"/>
       <l:template name="sect5" text="“%t”"/>
       <l:template name="section" text="“%t”"/>
       <l:template name="simplesect" text="“%t”"/>
    </l:context>
  </l:l10n>
</l:i18n>

<xsl:template match="table" mode="label.markup"/>

<xsl:param name="chapter.autolabel" select="0"/>

<xsl:param name="formal.title.placement">   <!-- Where does the title go, relative to the object -->
figure after
example before
equation before
table before
procedure before
task before
</xsl:param>

</xsl:stylesheet>
