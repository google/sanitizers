%%
%% This is file `acmart.cls',
%% generated with the docstrip utility.
%%
%% The original source files were:
%%
%% acmart.dtx  (with options: `class')
%% 
%% IMPORTANT NOTICE:
%% 
%% For the copyright see the source file.
%% 
%% Any modified versions of this file must be renamed
%% with new filenames distinct from acmart.cls.
%% 
%% For distribution of the original source see the terms
%% for copying and modification in the file acmart.dtx.
%% 
%% This generated file may be distributed as long as the
%% original source files, as listed above, are part of the
%% same distribution. (The sources need not necessarily be
%% in the same archive or directory.)
%% \CharacterTable
%%  {Upper-case    \A\B\C\D\E\F\G\H\I\J\K\L\M\N\O\P\Q\R\S\T\U\V\W\X\Y\Z
%%   Lower-case    \a\b\c\d\e\f\g\h\i\j\k\l\m\n\o\p\q\r\s\t\u\v\w\x\y\z
%%   Digits        \0\1\2\3\4\5\6\7\8\9
%%   Exclamation   \!     Double quote  \"     Hash (number) \#
%%   Dollar        \$     Percent       \%     Ampersand     \&
%%   Acute accent  \'     Left paren    \(     Right paren   \)
%%   Asterisk      \*     Plus          \+     Comma         \,
%%   Minus         \-     Point         \.     Solidus       \/
%%   Colon         \:     Semicolon     \;     Less than     \<
%%   Equals        \=     Greater than  \>     Question mark \?
%%   Commercial at \@     Left bracket  \[     Backslash     \\
%%   Right bracket \]     Circumflex    \^     Underscore    \_
%%   Grave accent  \`     Left brace    \{     Vertical bar  \|
%%   Right brace   \}     Tilde         \~}

\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{acmart}
[2023/12/29 v2.01 Typesetting articles for the Association for Computing Machinery]
\def\@classname{acmart}
\InputIfFileExists{acmart-preload-hook.tex}{%
  \ClassWarning{\@classname}{%
    I am loading acmart-preload-hook.tex. You are fully responsible
    for any problems from now on.}}{}
\RequirePackage{xkeyval}
\RequirePackage{xstring}
\RequirePackage{iftex}
\define@choicekey*+{acmart.cls}{format}[\ACM@format\ACM@format@nr]{%
  manuscript, acmsmall, acmlarge, acmtog, sigconf, siggraph,
  sigplan, sigchi, sigchi-a, acmengage, acmcp}[manuscript]{}{%
  \ClassError{\@classname}{The option format must be manuscript,
    acmsmall, acmlarge, acmtog, sigconf, siggraph,
    sigplan, sigchi or sigchi-a}}
\def\@DeclareACMFormat#1{\DeclareOptionX{#1}{\setkeys{acmart.cls}{format=#1}}}
\@DeclareACMFormat{manuscript}
\@DeclareACMFormat{acmsmall}
\@DeclareACMFormat{acmlarge}
\@DeclareACMFormat{acmtog}
\@DeclareACMFormat{sigconf}
\@DeclareACMFormat{siggraph}
\@DeclareACMFormat{sigplan}
\@DeclareACMFormat{sigchi}
\@DeclareACMFormat{sigchi-a}
\@DeclareACMFormat{acmengage}
\@DeclareACMFormat{acmcp}
\ExecuteOptionsX{format}
\define@boolkey+{acmart.cls}[@ACM@]{screen}[true]{%
  \if@ACM@screen
    \PackageInfo{\@classname}{Using screen mode}%
  \else
    \PackageInfo{\@classname}{Not using screen mode}%
  \fi}{\PackageError{\@classname}{The option screen can be either true or
    false}}
\ExecuteOptionsX{screen=false}
\define@boolkey+{acmart.cls}[@ACM@]{urlbreakonhyphens}[true]{%
  \if@ACM@urlbreakonhyphens
    \PackageInfo{\@classname}{Using breaking urls on hyphens}%
  \else
    \PackageInfo{\@classname}{Not breaking urls on hyphens}%
  \fi}{\PackageError{\@classname}{The option urlbreakonhyphens can be either true or
    false}}
\ExecuteOptionsX{urlbreakonhyphens=true}
\define@boolkey+{acmart.cls}[@ACM@]{acmthm}[true]{%
  \if@ACM@acmthm
    \PackageInfo{\@classname}{Requiring acmthm}%
  \else
    \PackageInfo{\@classname}{Suppressing acmthm}%
  \fi}{\PackageError{\@classname}{The option acmthm can be either true or
    false}}
\ExecuteOptionsX{acmthm=true}
\define@boolkey+{acmart.cls}[@ACM@]{review}[true]{%
  \if@ACM@review
    \PackageInfo{\@classname}{Using review mode}%
    \AtBeginDocument{\@ACM@printfoliostrue}%
  \else
    \PackageInfo{\@classname}{Not using review mode}%
  \fi}{\PackageError{\@classname}{The option review can be either true or
    false}}
\ExecuteOptionsX{review=false}
\define@boolkey+{acmart.cls}[@ACM@]{authorversion}[true]{%
  \if@ACM@authorversion
    \PackageInfo{\@classname}{Using authorversion mode}%
  \else
    \PackageInfo{\@classname}{Not using authorversion mode}%
  \fi}{\PackageError{\@classname}{The option authorversion can be either true or
    false}}
\ExecuteOptionsX{authorversion=false}
\define@boolkey+{acmart.cls}[@ACM@]{nonacm}[true]{%
  \if@ACM@nonacm
    \PackageInfo{\@classname}{Using nonacm mode}%
    \AtBeginDocument{\@ACM@printacmreffalse}%
    % in 'nonacm' mode we disable the "ACM Reference Format"
    % printing by default, but this can be re-enabled by the
    % user using \settopmatter{printacmref=true}
  \else
    \PackageInfo{\@classname}{Not using nonacm mode}%
  \fi}{\PackageError{\@classname}{The option nonacm can be either true or
    false}}
\ExecuteOptionsX{nonacm=false}
\define@boolkey+{acmart.cls}[@ACM@]{balance}[true]{}{%
  \PackageError{\@classname}{The option balance can be either true or
    false}}
\ExecuteOptionsX{balance}
\define@boolkey+{acmart.cls}[@ACM@]{pbalance}[true]{}{%
  \PackageError{\@classname}{The option pbalance can be either true or
    false}}
\ExecuteOptionsX{pbalance=false}
\define@boolkey+{acmart.cls}[@ACM@]{natbib}[true]{%
  \if@ACM@natbib
    \PackageInfo{\@classname}{Explicitly selecting natbib mode}%
  \else
    \PackageInfo{\@classname}{Explicitly deselecting natbib mode}%
  \fi}{\PackageError{\@classname}{The option natbib can be either true or
    false}}
\ExecuteOptionsX{natbib=true}
\define@boolkey+{acmart.cls}[@ACM@]{anonymous}[true]{%
  \if@ACM@anonymous
    \PackageInfo{\@classname}{Using anonymous mode}%
  \else
    \PackageInfo{\@classname}{Not using anonymous mode}%
  \fi}{\PackageError{\@classname}{The option anonymous can be either true or
    false}}
\ExecuteOptionsX{anonymous=false}
\define@boolkey+{acmart.cls}[@ACM@]{timestamp}[true]{%
  \if@ACM@timestamp
    \PackageInfo{\@classname}{Using timestamp mode}%
  \else
    \PackageInfo{\@classname}{Not using timestamp mode}%
  \fi}{\PackageError{\@classname}{The option timestamp can be either true or
    false}}
\ExecuteOptionsX{timestamp=false}
\define@boolkey+{acmart.cls}[@ACM@]{authordraft}[true]{%
  \if@ACM@authordraft
    \PackageInfo{\@classname}{Using authordraft mode}%
    \@ACM@timestamptrue
    \@ACM@reviewtrue
  \else
    \PackageInfo{\@classname}{Not using authordraft mode}%
  \fi}{\PackageError{\@classname}{The option authordraft can be either true or
    false}}
\ExecuteOptionsX{authordraft=false}
\def\ACM@fontsize{}
\DeclareOptionX{8pt}{\edef\ACM@fontsize{\CurrentOption}}
\DeclareOptionX{9pt}{\edef\ACM@fontsize{\CurrentOption}}
\DeclareOptionX{10pt}{\edef\ACM@fontsize{\CurrentOption}}
\DeclareOptionX{11pt}{\edef\ACM@fontsize{\CurrentOption}}
\DeclareOptionX{12pt}{\edef\ACM@fontsize{\CurrentOption}}
\def\ACM@languages{}
\DeclareOptionX{language}{%
  \ifx\ACM@languages\@empty
  \gdef\ACM@languages{english}\fi
  \g@addto@macro\ACM@languages{, #1}}
\DeclareOptionX{draft}{\PassOptionsToClass{\CurrentOption}{amsart}}
\DeclareOptionX{*}{\PassOptionsToClass{\CurrentOption}{amsart}}
\ProcessOptionsX
\ClassInfo{\@classname}{Using format \ACM@format, number \ACM@format@nr}
\newif\if@ACM@manuscript
\newif\if@ACM@journal
\newif\if@ACM@journal@bibstrip
\newif\if@ACM@sigchiamode
\newif\if@ACM@engage
\@ACM@engagefalse
\newif\if@ACM@acmcp
\@ACM@acmcpfalse
\ifnum\ACM@format@nr=5\relax % siggraph
\ClassWarning{\@classname}{%
  The format siggraph is now obsolete.\MessageBreak
  I am switching to sigconf.}
  \setkeys{acmart.cls}{format=sigconf}
\fi
\ifnum\ACM@format@nr=7\relax % sigchi
\ClassWarning{\@classname}{%
  The format sigchi is now obsolete.\MessageBreak
  I am switching to sigconf.}
  \setkeys{acmart.cls}{format=sigconf}
\fi
\ifnum\ACM@format@nr=8\relax % sigchi
\ClassWarning{\@classname}{%
  ACM SIGCHI has retired the SIGCHI-A template\MessageBreak
  effective immediately. ACM is keeping this template\MessageBreak
  option available to authors who are working on legacy\MessageBreak
  documents only. ACM will not, under any circumstances,\MessageBreak
  accept documents in this format for publication and\MessageBreak
  will not offer technical support to the authors who use\MessageBreak
  this template.\MessageBreak
  ACM SIGCHI is directing Conference leaders and\MessageBreak
  authors to publish their articles using the SIGCONF\MessageBreak
  template call.}
\fi
\ifnum\ACM@format@nr=0\relax
  \@ACM@manuscripttrue
\else
  \@ACM@manuscriptfalse
\fi
\@ACM@sigchiamodefalse
\ifcase\ACM@format@nr
\relax % manuscript
  \@ACM@journaltrue
\or % acmsmall
  \@ACM@journaltrue
\or % acmlarge
  \@ACM@journaltrue
\or % acmtog
  \@ACM@journaltrue
\or % sigconf
  \@ACM@journalfalse
\or % siggraph
  \@ACM@journalfalse
 \or % sigplan
  \@ACM@journalfalse
 \or % sigchi
  \@ACM@journalfalse
\or % sigchi-a
  \@ACM@journalfalse
  \@ACM@sigchiamodetrue
\or % acmengage
  \@ACM@journalfalse
  \@ACM@engagetrue
\or % acmcp
  \@ACM@journaltrue
  \@ACM@acmcptrue
  \AtBeginDocument{\@ACM@printacmreffalse}%
\fi
\if@ACM@journal
 \@ACM@journal@bibstriptrue
\else
 \@ACM@journal@bibstripfalse
\fi
\ifx\ACM@fontsize\@empty
  \ifcase\ACM@format@nr
  \relax % manuscript
    \def\ACM@fontsize{9pt}%
  \or % acmsmall
    \def\ACM@fontsize{10pt}%
  \or % acmlarge
    \def\ACM@fontsize{10pt}%
  \or % acmtog
    \def\ACM@fontsize{9pt}%
  \or % sigconf
    \def\ACM@fontsize{9pt}%
  \or % siggraph
    \def\ACM@fontsize{9pt}%
   \or % sigplan
    \def\ACM@fontsize{10pt}%
   \or % sigchi
    \def\ACM@fontsize{9pt}%
  \or % sigchi-a
    \def\ACM@fontsize{10pt}%
  \or % acmengage
    \def\ACM@fontsize{10pt}%
  \or % acmcp
    \def\ACM@fontsize{9pt}%
  \fi
\fi
\ClassInfo{\@classname}{Using fontsize \ACM@fontsize}
\LoadClass[\ACM@fontsize, reqno]{amsart}
\RequirePackage{microtype}
\RequirePackage{etoolbox}
\RequirePackage{booktabs}
\RequirePackage{refcount}
\RequirePackage{totpages}
\RequirePackage{environ}
\if@ACM@manuscript
\RequirePackage{setspace}
\onehalfspacing
\fi
\RequirePackage{textcase}
\if@ACM@acmcp
\RequirePackage{framed}
\RequirePackage{zref-savepos, zref-user}
\fi
\newdimen\@ACM@acmcp@delta
\@ACM@acmcp@delta=0pt\relax
\if@ACM@natbib
  \RequirePackage{natbib}
  \renewcommand{\bibsection}{%
     \section*{\refname}%
     \phantomsection\addcontentsline{toc}{section}{\refname}%
  }
  \renewcommand{\bibfont}{\bibliofont}
  \renewcommand\setcitestyle[1]{
  \@for\@tempa:=#1\do
  {\def\@tempb{round}\ifx\@tempa\@tempb
     \renewcommand\NAT@open{(}\renewcommand\NAT@close{)}\fi
   \def\@tempb{square}\ifx\@tempa\@tempb
     \renewcommand\NAT@open{[}\renewcommand\NAT@close{]}\fi
   \def\@tempb{angle}\ifx\@tempa\@tempb
     \renewcommand\NAT@open{$<$}\renewcommand\NAT@close{$>$}\fi
   \def\@tempb{curly}\ifx\@tempa\@tempb
     \renewcommand\NAT@open{\{}\renewcommand\NAT@close{\}}\fi
   \def\@tempb{semicolon}\ifx\@tempa\@tempb
     \renewcommand\NAT@sep{;}\fi
   \def\@tempb{colon}\ifx\@tempa\@tempb
     \renewcommand\NAT@sep{;}\fi
   \def\@tempb{comma}\ifx\@tempa\@tempb
     \renewcommand\NAT@sep{,}\fi
   \def\@tempb{authoryear}\ifx\@tempa\@tempb
     \NAT@numbersfalse\fi
   \def\@tempb{numbers}\ifx\@tempa\@tempb
     \NAT@numberstrue\NAT@superfalse\fi
   \def\@tempb{super}\ifx\@tempa\@tempb
     \NAT@numberstrue\NAT@supertrue\fi
   \def\@tempb{nobibstyle}\ifx\@tempa\@tempb
     \let\bibstyle=\@gobble\fi
   \def\@tempb{bibstyle}\ifx\@tempa\@tempb
     \let\bibstyle=\@citestyle\fi
   \def\@tempb{sort}\ifx\@tempa\@tempb
     \def\NAT@sort{\@ne}\fi
   \def\@tempb{nosort}\ifx\@tempa\@tempb
     \def\NAT@sort{\z@}\fi
   \def\@tempb{compress}\ifx\@tempa\@tempb
     \def\NAT@cmprs{\@ne}\fi
   \def\@tempb{nocompress}\ifx\@tempa\@tempb
     \def\NAT@cmprs{\z@}\fi
   \def\@tempb{sort&compress}\ifx\@tempa\@tempb
     \def\NAT@sort{\@ne}\def\NAT@cmprs{\@ne}\fi
   \def\@tempb{mcite}\ifx\@tempa\@tempb
     \let\NAT@merge\@ne\fi
   \def\@tempb{merge}\ifx\@tempa\@tempb
     \@ifnum{\NAT@merge<\tw@}{\let\NAT@merge\tw@}{}\fi
   \def\@tempb{elide}\ifx\@tempa\@tempb
     \@ifnum{\NAT@merge<\thr@@}{\let\NAT@merge\thr@@}{}\fi
   \def\@tempb{longnamesfirst}\ifx\@tempa\@tempb
     \NAT@longnamestrue\fi
   \def\@tempb{nonamebreak}\ifx\@tempa\@tempb
     \def\NAT@nmfmt#1{\mbox{\NAT@up#1}}\fi
   \expandafter\NAT@find@eq\@tempa=\relax\@nil
   \if\@tempc\relax\else
     \expandafter\NAT@rem@eq\@tempc
     \def\@tempb{open}\ifx\@tempa\@tempb
      \xdef\NAT@open{\@tempc}\fi
     \def\@tempb{close}\ifx\@tempa\@tempb
      \xdef\NAT@close{\@tempc}\fi
     \def\@tempb{aysep}\ifx\@tempa\@tempb
      \xdef\NAT@aysep{\@tempc}\fi
     \def\@tempb{yysep}\ifx\@tempa\@tempb
      \xdef\NAT@yrsep{\@tempc}\fi
     \def\@tempb{notesep}\ifx\@tempa\@tempb
      \xdef\NAT@cmt{\@tempc}\fi
     \def\@tempb{citesep}\ifx\@tempa\@tempb
      \xdef\NAT@sep{\@tempc}\fi
   \fi
  }%
  \NAT@@setcites
  }
  \renewcommand\citestyle[1]{%
    \ifcsname bibstyle@#1\endcsname%
    \csname bibstyle@#1\endcsname\let\bibstyle\@gobble%
    \else%
    \@latex@error{Undefined `#1' citestyle}%
    \fi
  }%
\fi
\newcommand{\bibstyle@acmauthoryear}{%
  \setcitestyle{%
    authoryear,%
    open={[},close={]},citesep={;},%
    aysep={},yysep={,},%
    notesep={, }}}
\newcommand{\bibstyle@acmnumeric}{%
  \setcitestyle{%
    numbers,sort&compress,%
    open={[},close={]},citesep={,},%
    notesep={, }}}
\if@ACM@natbib
\citestyle{acmnumeric}
\fi
\if@ACM@journal
  \renewcommand\keywordsname{Additional Key Words and Phrases}%
\else
  \renewcommand\keywordsname{Keywords}%
\fi
\if@ACM@engage
   \renewcommand\abstractname{Synopsis}%
\fi
\ifx\ACM@languages\@empty
\else
  \RequirePackage[\ACM@languages]{babel}%
  \addto\captionsenglish{%
      \if@ACM@journal
        \renewcommand\keywordsname{Additional Key Words and Phrases}%
      \else
        \renewcommand\keywordsname{Keywords}%
      \fi
      \renewcommand\acksname{Acknowledgements}%
      \if@ACM@engage
         \renewcommand\abstractname{Synopsis}%
      \fi
  }%
  \addto\captionsfrench{%
      \if@ACM@journal
        \renewcommand\keywordsname{Mots Clés et Phrases Supplémentaires}%
      \else
        \renewcommand\keywordsname{Mots clés}%
      \fi
      \renewcommand\acksname{Remerciements}%
  }%
  \addto\captionsgerman{%
      \if@ACM@journal
        \renewcommand\keywordsname{Zusätzliche Schlagwörter und Phrasen}%
      \else
        \renewcommand\keywordsname{Schlagwörter}%
      \fi
      \renewcommand\acksname{Danksagungen}%
  }%
  \addto\captionsspanish{%
      \if@ACM@journal
        \renewcommand\keywordsname{Palabras y Frases Claves Adicionales}%
      \else
        \renewcommand\keywordsname{Palabras claves}%
      \fi
      \renewcommand\acksname{Expresiones de gratitud}%
  }%
\fi
\newcommand\ACM@lang@check[1]{%
  \ifx\ACM@languages\@empty\relax
  \ClassError{\@classname}{%
    Command \string#1 \MessageBreak is used in monlingual document}{%
    You used a command (\string#1) \MessageBreak
    that does not have a meaning \MessageBreak
    unless are languages are defined. \MessageBreak
    Please choose the languages in \string\documentclass
    \MessageBreak
    (e.g. \string\documentclass[languages={french, english}]{acmart}),
    \MessageBreak
    or delete the command.}%
  \fi}
\def\@translatedtitle{}
\newcommand\translatedtitle[2]{\ACM@lang@check{\translatedtitle}%
\g@addto@macro\@translatedtitle{\par\foreignlanguage{#1}{#2}}}
\def\@translatedsubtitle{}
\newcommand\translatedsubtitle[2]{\ACM@lang@check{\translatedsubtitle}%
\g@addto@macro\@translatedsubtitle{\par\foreignlanguage{#1}{#2}}}
\def\@translatedkeywords{}
\newcommand\translatedkeywords[2]{\ACM@lang@check{\translatedkeywords}%
\g@addto@macro\@translatedkeywords{\@mktranslatedkeywords{#1}{#2}}}
\def\@translatedabstracts{}
\newenvironment{translatedabstract}[1]{\Collect@Body
  \@savetranslatedabstract\@mktranslatedabstract{#1}}{}
\long\def\@savetranslatedabstract#1{\if@ACM@maketitle@typeset
  \ClassError{\@classname}{Abstract must be defined before maketitle
    command. Please move it!}\fi
  \ACM@lang@check{translatedabstract}%
  \g@addto@macro\@translatedabstracts{\bgroup#1\egroup}}
\def\@startsection#1#2#3#4#5#6{%
  \if@noskipsec \leavevmode \fi
  \par
  \@tempskipa #4\relax
  \@afterindenttrue
  \ifdim \@tempskipa <\z@
    \@tempskipa -\@tempskipa \@afterindentfalse
  \fi
  \if@nobreak
    \everypar{}%
  \else
    \addpenalty\@secpenalty\addvspace\@tempskipa
  \fi
  \@ifstar
    {\@ssect{#3}{#4}{#5}{#6}}%
    {\@dblarg{\@sect{#1}{#2}{#3}{#4}{#5}{#6}}}}
\def\@sect#1#2#3#4#5#6[#7]#8{%
  \edef\@toclevel{\ifnum#2=\@m 0\else\number#2\fi}%
  \ifnum #2>\c@secnumdepth
    \let\@svsec\@empty
  \else
    \refstepcounter{#1}%
    \protected@edef\@svsec{\@seccntformat{#1}\relax}%
  \fi
  \@tempskipa #5\relax
  \ifdim \@tempskipa>\z@
    \begingroup
      #6{%
        \@hangfrom{\hskip #3\relax\@svsec}%
          \interlinepenalty \@M #8\@@par}%
    \endgroup
    \csname #1mark\endcsname{#7}%
    \ifnum #2>\c@secnumdepth \else
        \@tochangmeasure{\csname the#1\endcsname}%
    \fi
    \addcontentsline{toc}{#1}{%
      \ifnum #2>\c@secnumdepth \else
        \protect\numberline{\csname the#1\endcsname}%
      \fi
      #7}%
  \else
    \def\@svsechd{%
      #6{\hskip #3\relax
      \@svsec #8}%
      \csname #1mark\endcsname{#7}%
      \ifnum #2>\c@secnumdepth \else
        \@tochangmeasure{\csname the#1\endcsname\space}%
      \fi
      \addcontentsline{toc}{#1}{%
        \ifnum #2>\c@secnumdepth \else
          \protect\numberline{\csname the#1\endcsname}%
        \fi
        #7}}%
  \fi
  \@xsect{#5}}
\def\@xsect#1{%
  \@tempskipa #1\relax
  \ifdim \@tempskipa>\z@
    \par \nobreak
    \vskip \@tempskipa
    \@afterheading
  \else
    \@nobreakfalse
    \global\@noskipsectrue
    \everypar{%
      \if@noskipsec
        \global\@noskipsecfalse
       {\setbox\z@\lastbox}%
        \clubpenalty\@M
        \begingroup \@svsechd \endgroup
        \unskip
        \@tempskipa #1\relax
        \hskip -\@tempskipa
      \else
        \clubpenalty \@clubpenalty
        \everypar{}%
      \fi}%
  \fi
  \ignorespaces}
\def\@seccntformat#1{\csname the#1\endcsname\quad}
\def\@ssect#1#2#3#4#5{%
  \@tempskipa #3\relax
  \ifdim \@tempskipa>\z@
    \begingroup
      #4{%
        \@hangfrom{\hskip #1}%
          \interlinepenalty \@M #5\@@par}%
    \endgroup
  \else
    \def\@svsechd{#4{\hskip #1\relax #5}}%
  \fi
  \@xsect{#3}}
\def\@starttoc#1#2{\begingroup\makeatletter
  \setTrue{#1}%
  \par\removelastskip\vskip\z@skip
  \@startsection{section}\@M\z@{\linespacing\@plus\linespacing}%
    {.5\linespacing}{\centering\contentsnamefont}{#2}%
  \@input{\jobname.#1}%
  \if@filesw
    \@xp\newwrite\csname tf@#1\endcsname
    \immediate\@xp\openout\csname tf@#1\endcsname \jobname.#1\relax
  \fi
  \global\@nobreakfalse \endgroup
  \addvspace{32\p@\@plus14\p@}%
}
\def\l@section{\@tocline{1}{0pt}{1pc}{2pc}{}}
\def\l@subsection{\@tocline{2}{0pt}{1pc}{3pc}{}}
\def\l@subsubsection{\@tocline{3}{0pt}{1pc}{5pc}{}}
\def\@makefntext{\noindent\@makefnmark}
\if@ACM@sigchiamode
\long\def\@footnotetext#1{\marginpar{%
    \reset@font\small
    \interlinepenalty\interfootnotelinepenalty
    \protected@edef\@currentlabel{%
       \csname p@footnote\endcsname\@thefnmark
    }%
    \color@begingroup
      \@makefntext{%
        \rule\z@\footnotesep\ignorespaces#1\@finalstrut\strutbox}%
    \color@endgroup}}%
\fi
\long\def\@mpfootnotetext#1{%
  \global\setbox\@mpfootins\vbox{%
    \unvbox\@mpfootins
    \reset@font\footnotesize
    \hsize\columnwidth
    \@parboxrestore
    \protected@edef\@currentlabel
         {\csname p@mpfootnote\endcsname\@thefnmark}%
    \color@begingroup\centering
      \@makefntext{%
        \rule\z@\footnotesep\ignorespaces#1\@finalstrut\strutbox}%
    \color@endgroup}}
\def\@makefnmark{\hbox{\@textsuperscript{\normalfont\@thefnmark}}}
\let\@footnotemark@nolink\@footnotemark
\let\@footnotetext@nolink\@footnotetext
\RequirePackage[bookmarksnumbered,unicode]{hyperref}
\RequirePackage{hyperxmp}
\pdfstringdefDisableCommands{%
  \def\addtocounter#1#2{}%
  \def\unskip{}%
  \def\textbullet{- }%
  \def\textrightarrow{ -> }%
  \def\footnotemark{}%
}
\urlstyle{rm}
\ifcase\ACM@format@nr
\relax % manuscript
\or % acmsmall
\or % acmlarge
\or % acmtog
\or % sigconf
\or % siggraph
\or % sigplan
  \urlstyle{sf}
\or % sigchi
\or % sigchi-a
  \urlstyle{sf}
\or % acmengage
\or % acmcp
\fi
\AtEndPreamble{%
  \if@ACM@urlbreakonhyphens
    \def\do@url@hyp{\do\-}%
  \fi
  \if@ACM@screen
    \hypersetup{colorlinks,
      linkcolor=ACMPurple,
      citecolor=ACMPurple,
      urlcolor=ACMDarkBlue,
      filecolor=ACMDarkBlue}
    \else
    \hypersetup{hidelinks}
  \fi
  \hypersetup{pdflang={en},
    pdfdisplaydoctitle}}
\if@ACM@natbib
  \let\citeN\cite
  \let\cite\citep
  \let\citeANP\citeauthor
  \let\citeNN\citeyearpar
  \let\citeyearNP\citeyear
  \let\citeNP\citealt
  \DeclareRobustCommand\citeA
     {\begingroup\NAT@swafalse
       \let\NAT@ctype\@ne\NAT@partrue\NAT@fullfalse\NAT@open\NAT@citetp}%
  \providecommand\newblock{}%
\else
  \AtBeginDocument{%
    \let\shortcite\cite%
    \providecommand\citename[1]{#1}}
\fi
\newcommand\shortcite[2][]{%
  \ifNAT@numbers\cite[#1]{#2}\else\citeyearpar[#1]{#2}\fi}
\def\bibliographystyle#1{%
  \ifx\@begindocumenthook\@undefined\else
    \expandafter\AtBeginDocument
  \fi
    {\if@filesw
       \immediate\write\@auxout{\string\bibstyle{#1}}%
     \fi}}
\RequirePackage{graphicx}
\RequirePackage[prologue]{xcolor}
\definecolor[named]{ACMBlue}{cmyk}{1,0.1,0,0.1}
\definecolor[named]{ACMYellow}{cmyk}{0,0.16,1,0}
\definecolor[named]{ACMOrange}{cmyk}{0,0.42,1,0.01}
\definecolor[named]{ACMRed}{cmyk}{0,0.90,0.86,0}
\definecolor[named]{ACMLightBlue}{cmyk}{0.49,0.01,0,0}
\definecolor[named]{ACMGreen}{cmyk}{0.20,0,1,0.19}
\definecolor[named]{ACMPurple}{cmyk}{0.55,1,0,0.15}
\definecolor[named]{ACMDarkBlue}{cmyk}{1,0.58,0,0.21}
\if@ACM@authordraft
  \RequirePackage{draftwatermark}
  \SetWatermarkFontSize{0.5in}
  \SetWatermarkColor[gray]{.9}
  \SetWatermarkText{\parbox{12em}{\centering
      Unpublished working draft.\\
      Not for distribution.}}
\else
  \if@ACM@sigchiamode
    \if@ACM@nonacm\else
      \RequirePackage{draftwatermark}
      \SetWatermarkFontSize{0.5in}
      \SetWatermarkColor[gray]{.9}
      \SetWatermarkText{\parbox{12em}{\centering
          Legacy document. \\
          Not for publication in an ACM venue}}
    \fi
  \fi
\fi
\RequirePackage{geometry}
\ifcase\ACM@format@nr
\relax % manuscript
   \geometry{letterpaper,head=13pt,
   marginparwidth=6pc,heightrounded}%
\or % acmsmall
   \geometry{twoside=true,
     includeheadfoot, head=13pt, foot=2pc,
     paperwidth=6.75in, paperheight=10in,
     top=58pt, bottom=44pt, inner=46pt, outer=46pt,
     marginparwidth=2pc,heightrounded
   }%
\or % acmlarge
   \geometry{twoside=true, head=13pt, foot=2pc,
     paperwidth=8.5in, paperheight=11in,
     includeheadfoot,
     top=78pt, bottom=114pt, inner=81pt, outer=81pt,
     marginparwidth=4pc,heightrounded
     }%
\or % acmtog
   \geometry{twoside=true, head=13pt, foot=2pc,
     paperwidth=8.5in, paperheight=11in,
     includeheadfoot, columnsep=24pt,
     top=52pt, bottom=75pt, inner=52pt, outer=52pt,
     marginparwidth=2pc,heightrounded
     }%
\or % sigconf
   \geometry{twoside=true, head=13pt,
     paperwidth=8.5in, paperheight=11in,
     includeheadfoot, columnsep=2pc,
     top=57pt, bottom=73pt, inner=54pt, outer=54pt,
     marginparwidth=2pc,heightrounded
     }%
\or % siggraph
   \geometry{twoside=true, head=13pt,
     paperwidth=8.5in, paperheight=11in,
     includeheadfoot, columnsep=2pc,
     top=57pt, bottom=73pt, inner=54pt, outer=54pt,
     marginparwidth=2pc,heightrounded
     }%
\or % sigplan
   \geometry{twoside=true, head=13pt,
     paperwidth=8.5in, paperheight=11in,
     includeheadfoot=false, columnsep=2pc,
     top=1in, bottom=1in, inner=0.75in, outer=0.75in,
     marginparwidth=2pc,heightrounded
     }%
\or % sigchi
   \geometry{twoside=true, head=13pt,
     paperwidth=8.5in, paperheight=11in,
     includeheadfoot, columnsep=2pc,
     top=66pt, bottom=73pt, inner=54pt, outer=54pt,
     marginparwidth=2pc,heightrounded
     }%
\or % sigchi-a
   \geometry{twoside=false, head=13pt,
     paperwidth=11in, paperheight=8.5in,
     includeheadfoot, marginparsep=72pt,
     marginparwidth=170pt, columnsep=20pt,
     top=72pt, bottom=72pt, left=314pt, right=72pt
     }%
     \@mparswitchfalse
     \reversemarginpar
\or % acmengage
   \geometry{twoside=true, head=13pt,
     paperwidth=8.5in, paperheight=11in,
     includeheadfoot, columnsep=2pc,
     top=57pt, bottom=73pt, inner=54pt, outer=54pt,
     marginparwidth=2pc,heightrounded
     }%
\or % acmcp
   \geometry{twoside=true,
     includeheadfoot, head=13pt, foot=2pc,
     paperwidth=6.75in, paperheight=10in,
     top=58pt, bottom=44pt, inner=46pt, outer=46pt,
     marginparwidth=2pc,heightrounded
   }%
\fi
\setlength\parindent{10\p@}
\setlength\parskip{\z@}
\ifcase\ACM@format@nr
\relax % manuscript
\or % acmsmall
\or % acmlarge
\or % acmtog
  \setlength\parindent{9\p@}%
\or % sigconf
\or % siggraph
\or % sigplan
\or % sigchi
\or % sigchi-a
\or % acmengage
\or % acmcp
\fi
\setlength\normalparindent{\parindent}
\def\copyrightpermissionfootnoterule{\kern-3\p@
  \hrule \@width \columnwidth \kern 2.6\p@}
\RequirePackage{manyfoot}
\SelectFootnoteRule[2]{copyrightpermission}
\DeclareNewFootnote{authorsaddresses}
\SelectFootnoteRule[2]{copyrightpermission}
\DeclareNewFootnote{copyrightpermission}
\def\footnoterule{\kern-3\p@
  \hrule \@width 4pc \kern 2.6\p@}
\def\endminipage{%
    \par
    \unskip
    \ifvoid\@mpfootins\else
      \vskip\skip\@mpfootins
      \normalcolor
      \unvbox\@mpfootins
    \fi
    \@minipagefalse
  \color@endgroup
  \egroup
  \expandafter\@iiiparbox\@mpargs{\unvbox\@tempboxa}}
\def\@textbottom{\vskip \z@ \@plus 1pt}
\let\@texttop\relax
\ifcase\ACM@format@nr
\relax % manuscript
\or % acmsmall
\or % acmlarge
\or % acmtog
  \flushbottom
\or % sigconf
  \flushbottom
\or % siggraph
  \flushbottom
\or % sigplan
  \flushbottom
\or % sigchi
  \flushbottom
\or % sigchi-a
\or % acmengage
  \flushbottom
\or % acmcp
  \flushbottom
\fi
\ifPDFTeX
\input{glyphtounicode}
\pdfglyphtounicode{f_f}{FB00}
\pdfglyphtounicode{f_f_i}{FB03}
\pdfglyphtounicode{f_f_l}{FB04}
\pdfglyphtounicode{f_i}{FB01}
\pdfglyphtounicode{t_t}{0074 0074}
\pdfglyphtounicode{f_t}{0066 0074}
\pdfglyphtounicode{T_h}{0054 0068}
\pdfgentounicode=1
\RequirePackage{cmap}
\fi
\newif\if@ACM@newfonts
\@ACM@newfontstrue
\IfFileExists{libertine.sty}{}{\ClassWarning{\@classname}{You do not
    have the libertine package installed.  Please upgrade your
    TeX}\@ACM@newfontsfalse}
\IfFileExists{zi4.sty}{}{\ClassWarning{\@classname}{You do not
    have the inconsolata (zi4.sty) package installed.  Please upgrade your
    TeX}\@ACM@newfontsfalse}
\IfFileExists{newtxmath.sty}{}{\ClassWarning{\@classname}{You do not
    have the newtxmath package installed.  Please upgrade your
    TeX}\@ACM@newfontsfalse}
\if@ACM@newfonts
  \RequirePackage[T1]{fontenc}
  % Note that the order in which packages are loaded matters,
  % and the correct order depends on the LaTeX engine used.
  % See https://github.com/borisveytsman/acmart/issues/402
  % and https://github.com/borisveytsman/acmart/issues/410
  \ifxetex
    \RequirePackage[libertine]{newtxmath}
    \RequirePackage[tt=false]{libertine}
    \setmonofont[StylisticSet=3]{inconsolata}
  \else
    \ifluatex
      \RequirePackage[libertine]{newtxmath}
      \RequirePackage[tt=false]{libertine}
      \setmonofont[StylisticSet=3]{inconsolata}
    \else
       \RequirePackage[tt=false, type1=true]{libertine}
       \RequirePackage[varqu]{zi4}
       \RequirePackage[libertine]{newtxmath}
    \fi
  \fi
\fi
\let\liningnums\@undefined
\AtEndPreamble{%
  \DeclareTextFontCommand{\liningnums}{\libertineLF}}
\if@ACM@sigchiamode
  \renewcommand{\familydefault}{\sfdefault}
\fi
\newif\if@Description@present
\@Description@presenttrue
\newif\if@undescribed@images
\@undescribed@imagesfalse
\newcommand\Description[2][]{\global\@Description@presenttrue\ignorespaces}
\AtEndDocument{\if@undescribed@images
  \ClassWarningNoLine{\@classname}{Some images may lack descriptions}\fi}
\AtBeginEnvironment{figure}{\@Description@presentfalse
  \let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{figure*}{\@Description@presentfalse
  \let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtEndEnvironment{figure}{\if@Description@present\else
  \global\@undescribed@imagestrue
  \ClassWarning{\@classname}{A possible image without description}\fi}
\AtEndEnvironment{figure*}{\if@Description@present\else
  \global\@undescribed@imagestrue
  \ClassWarning{\@classname}{A possible image without description}\fi}
\AtBeginEnvironment{table}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{table*}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{algorithm}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{algorithm*}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{lstlisting}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{lstlisting*}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{minted}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{minted*}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{listing}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}
\AtBeginEnvironment{listing*}{\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig}

\RequirePackage{caption, float}
\captionsetup[table]{position=top}
\if@ACM@journal
  \captionsetup{labelfont={sf, small},
    textfont={sf, small}, margin=\z@}
  \captionsetup[figure]{name={Fig.}}
\else
  \captionsetup{labelfont={bf},
    textfont={bf}, labelsep=colon, margin=\z@}
  \ifcase\ACM@format@nr
  \relax % manuscript
  \or % acmsmall
  \or % acmlarge
  \or % acmtog
  \or % sigconf
  \or % siggraph
    \captionsetup{textfont={it}}
  \or % sigplan
    \captionsetup{labelfont={bf},
      textfont={normalfont}, labelsep=period, margin=\z@}
  \or % sigchi
    \captionsetup[figure]{labelfont={bf, small},
      textfont={bf, small}}
    \captionsetup[table]{labelfont={bf, small},
      textfont={bf, small}}
  \or % sigchi-a
    \captionsetup[figure]{labelfont={bf, small},
      textfont={bf, small}}
    \captionsetup[table]{labelfont={bf, small},
      textfont={bf, small}}
  \or % acmengage
  \or % acmcp
  \fi
\fi
\newfloat{sidebar}{}{sbar}
\floatname{sidebar}{Sidebar}
\renewenvironment{sidebar}{\Collect@Body\@sidebar}{}
\long\def\@sidebar#1{\bgroup\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig\captionsetup{type=sidebar}%
  \marginpar{\small#1}\egroup}
\newenvironment{marginfigure}{\Collect@Body\@marginfigure}{}
\long\def\@marginfigure#1{\bgroup
  \let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig
  \captionsetup{type=figure}%
  \marginpar{\@Description@presentfalse\centering
    \small#1\if@Description@present\else
      \global\@undescribed@imagestrue
      \ClassWarning{\@classname}{A possible image without description}
      \fi}%
  \egroup}
\newenvironment{margintable}{\Collect@Body\@margintable}{}
\long\def\@margintable#1{\bgroup\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig\captionsetup{type=table}%
  \marginpar{\centering\small#1}\egroup}
\newdimen\fulltextwidth
\fulltextwidth=\dimexpr(\textwidth+\marginparwidth+\marginparsep)
\if@ACM@sigchiamode
\def\@dblfloat{\bgroup\let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig\columnwidth=\fulltextwidth
  \let\@endfloatbox\@endwidefloatbox
  \def\@fpsadddefault{\def\@fps{tp}}%
  \@float}
\fi
\if@ACM@sigchiamode
\def\end@dblfloat{%
    \end@float\egroup}
\fi
\def\@endwidefloatbox{%
  \par\vskip\z@skip
  \@minipagefalse
  \outer@nobreak
  \egroup
  \color@endbox
  \global\setbox\@currbox=\vbox{\moveleft
    \dimexpr(\fulltextwidth-\textwidth)\box\@currbox}%
  \wd\@currbox=\textwidth
}
\ifcase\ACM@format@nr
\relax % manuscript
\or % acmsmall
\or % acmlarge
\or % acmtog
\or % sigconf
\or % siggraph
\or % sigplan
\def\labelenumi{\theenumi.}
\def\labelenumii{\theenumii.}
\def\labelenumiii{\theenumiii.}
\def\labelenumiv{\theenumiv.}
\or % sigchi
\or % sigchi-a
\or % acmengage
\or % acmcp
\fi
\newdimen\@ACM@labelwidth
\AtBeginDocument{%
  \setlength\labelsep{4pt}
  \setlength{\@ACM@labelwidth}{6.5pt}

  %% First-level list: when beginning after the first line of an
  %% indented paragraph or ending before an indented paragraph, labels
  %% should not hang to the left of the preceding/following text.
  \setlength\leftmargini{\z@}
  \addtolength\leftmargini{\parindent}
  \addtolength\leftmargini{2\labelsep}
  \addtolength\leftmargini{\@ACM@labelwidth}

  %% Second-level and higher lists.
  \setlength\leftmarginii{\z@}
  \addtolength\leftmarginii{0.5\labelsep}
  \addtolength\leftmarginii{\@ACM@labelwidth}
  \setlength\leftmarginiii{\leftmarginii}
  \setlength\leftmarginiv{\leftmarginiii}
  \setlength\leftmarginv{\leftmarginiv}
  \setlength\leftmarginvi{\leftmarginv}
  \@listi}
\newskip\listisep
\listisep\smallskipamount
\def\@listI{\leftmargin\leftmargini
  \labelwidth\leftmargini \advance\labelwidth-\labelsep
  \listparindent\z@
  \topsep\listisep}
\let\@listi\@listI
\def\@listii{\leftmargin\leftmarginii
  \labelwidth\leftmarginii \advance\labelwidth-\labelsep
  \topsep\z@skip}
\def\@listiii{\leftmargin\leftmarginiii
  \labelwidth\leftmarginiii \advance\labelwidth-\labelsep}
\def\@listiv{\leftmargin\leftmarginiv
  \labelwidth\leftmarginiv \advance\labelwidth-\labelsep}
\def\@listv{\leftmargin\leftmarginv
  \labelwidth\leftmarginv \advance\labelwidth-\labelsep}
\def\@listvi{\leftmargin\leftmarginvi
  \labelwidth\leftmarginvi \advance\labelwidth-\labelsep}
\renewcommand{\descriptionlabel}[1]{\upshape\bfseries #1}
\renewenvironment{description}{\list{}{%
    \labelwidth\@ACM@labelwidth
    \let\makelabel\descriptionlabel}%
}{
  \endlist
}
\let\enddescription=\endlist % for efficiency
\newif\if@ACM@maketitle@typeset
\@ACM@maketitle@typesetfalse
\define@choicekey*+{ACM}{acmJournal}[\@journalCode\@journalCode@nr]{%
  ACMJCSS,%
  CIE,%
  CSUR,%
  DGOV,%
  DLT,%
  DTRAP,%
  FAC,%
  GAMES,%
  HEALTH,%
  IMWUT,%
  JACM,%
  JATS,%
  JDIQ,%
  JDS,%
  JEA,%
  JERIC,%
  JETC,%
  JOCCH,%
  JRC,%
  PACMCGIT,%
  PACMHCI,%
  PACMMOD,%
  PACMNET,%
  PACMPL,%
  PACMSE,%
  POMACS,%
  TAAS,%
  TACCESS,%
  TACO,%
  TALG,%
  TALLIP,%
  TAP,%
  TCPS,%
  TDS,%
  TEAC,%
  TECS,%
  TELO,%
  THRI,%
  TIIS,%
  TIOT,%
  TISSEC,%
  TIST,%
  TKDD,%
  TMIS,%
  TOCE,%
  TOCHI,%
  TOCL,%
  TOCS,%
  TOCT,%
  TODAES,%
  TODS,%
  TOG,%
  TOIS,%
  TOIT,%
  TOMACS,%
  TOMM,%
  TOMPECS,%
  TOMS,%
  TOPC,%
  TOPS,%
  TOPLAS,%
  TOPML,%
  TORS,%
  TOS,%
  TOSEM,%
  TOSN,%
  TQC,%
  TRETS,%
  TSAS,%
  TSC,%
  TSLP,%
  TWEB,%
  FACMP%
}{%
\ifcase\@journalCode@nr
\relax % ACMJCSS
  \def\@journalName{ACM Journal on Computing and Sustainable Societies}%
  \def\@journalNameShort{ACM J. Comput. Sustain. Soc.}%
  \def\@permissionCodeOne{2834-5533}%
\or % CIE
  \def\@journalName{ACM Computers in Entertainment}%
  \def\@journalNameShort{ACM Comput. Entertain.}%
  \def\@permissionCodeOne{1544-3574}%
\or % CSUR
  \def\@journalName{ACM Computing Surveys}%
  \def\@journalNameShort{ACM Comput. Surv.}%
  \def\@permissionCodeOne{0360-0300}%
\or % DGOV
  \def\@journalName{Digital Government: Research and Practice}%
  \def\@journalNameShort{Digit. Gov. Res. Pract.}%
  \def\@permissionCodeOne{2639-0175}%
\or % DLT
  \def\@journalName{Distributed Ledger Technologies: Research and Practice}%
  \def\@journalNameShort{Distrib. Ledger Technol.}%
  \def\@permissionCodeOne{2769-6472}%
\or % DTRAP
  \def\@journalName{Digital Threats: Research and Practice}%
  \def\@journalNameShort{Digit. Threat. Res. Pract.}%
  \def\@permissionCodeOne{2576-5337}%
\or % FAC
  \def\@journalName{Formal Aspects of Computing}%
  \def\@journalNameShort{Form. Asp. Comput.}%
  \def\@permissionCodeOne{0934-5043}%
  \def\@permissionCodeTwo{1433-299X}%
\or % GAMES
  \def\@journalName{ACM Games: Research and Practice}%
  \def\@journalNameShort{ACM Games}%
  \def\@permissionCodeOne{2832-5516}%
\or % HEALTH
  \def\@journalName{ACM Transactions on Computing for Healthcare}%
  \def\@journalNameShort{ACM Trans. Comput. Healthcare}%
  \def\@permissionCodeOne{2637-8051}%
\or % IMWUT
  \def\@journalName{Proceedings of the ACM on Interactive, Mobile,
    Wearable and Ubiquitous Technologies}%
  \def\@journalNameShort{Proc. ACM Interact. Mob. Wearable Ubiquitous Technol.}%
  \def\@permissionCodeOne{2474-9567}%
  \@ACM@screentrue
  \PackageInfo{\@classname}{Using screen mode due to \@journalCode}%
\or % JACM
  \def\@journalName{Journal of the ACM}%
  \def\@journalNameShort{J. ACM}%
  \def\@permissionCodeOne{0004-5411}%
\or % JATS
  \def\@journalName{Journal on Autonomous Transportation Systems}%
  \def\@journalNameShort{ACM J. Auton. Transport. Syst.}%
  \def\@permissionCodeOne{2833-0528}%
\or % JDIQ
  \def\@journalName{ACM Journal of Data and Information Quality}%
  \def\@journalNameShort{ACM J. Data Inform. Quality}%
  \def\@permissionCodeOne{1936-1955}%
\or % JDS
  \def\@journalName{ACM/JMS Journal of Data Science}%
  \def\@journalNameShort{ACM/IMS J. Data Sci.}%
  \def\@permissionCodeOne{2831-3194}%
  \def\@permissionCodeTwo{2831-3194}%
\or % JEA
  \def\@journalName{ACM Journal of Experimental Algorithmics}%
  \def\@journalNameShort{ACM J. Exp. Algor.}%
  \def\@permissionCodeOne{1084-6654}%
\or % JERIC
  \def\@journalName{ACM Journal of Educational Resources in Computing}%
  \def\@journalNameShort{ACM J. Edu. Resources in Comput.}%
  \def\@permissionCodeOne{1073-0516}%
\or % JETC
  \def\@journalName{ACM Journal on Emerging Technologies in Computing Systems}%
  \def\@journalNameShort{ACM J. Emerg. Technol. Comput. Syst.}%
  \def\@permissionCodeOne{1550-4832}%
\or % JOCCH
  \def\@journalName{ACM Journal on Computing and Cultural Heritage}%
  \def\@journalNameShort{ACM J. Comput. Cult. Herit.}%
  \def\@permissionCodeOne{1556-4673}%
  \def\@permissionCodeTwo{1556-4711}%
\or % JRC
  \def\@journalName{ACM Journal on Responsible Computing}%
  \def\@journalNameShort{ACM J. Responsib. Comput.}%
  \def\@permissionCodeOne{2832-0565}%
\or % PACMCGIT
  \def\@journalName{Proceedings of the ACM on Computer Graphics and Interactive Techniques}%
  \def\@journalNameShort{Proc. ACM Comput. Graph. Interact. Tech.}%
  \def\@permissionCodeOne{2577-6193}%
  \@ACM@screentrue
  \PackageInfo{\@classname}{Using screen mode due to \@journalCode}%
\or % PACMHCI
  \def\@journalName{Proceedings of the ACM on Human-Computer Interaction}%
  \def\@journalNameShort{Proc. ACM Hum.-Comput. Interact.}%
  \def\@permissionCodeOne{2573-0142}%
  \@ACM@screentrue
  \PackageInfo{\@classname}{Using screen mode due to \@journalCode}%
\or % PACMMOD
  \def\@journalName{Proceedings of the ACM on Management of Data}%
  \def\@journalNameShort{Proc. ACM Manag. Data}%
  \def\@permissionCodeOne{2836-6573}%
\or % PACMNET
  \def\@journalName{Proceedings of the ACM on Networkng}%
  \def\@journalNameShort{Proc. ACM Netw.}%
  \def\@permissionCodeOne{2834-5509}%
\or % PACMPL
  \def\@journalName{Proceedings of the ACM on Programming Languages}%
  \def\@journalNameShort{Proc. ACM Program. Lang.}%
  \def\@permissionCodeOne{2475-1421}%
  \@ACM@screentrue
  \PackageInfo{\@classname}{Using screen mode due to \@journalCode}%
\or % PACMSE
  \def\@journalName{Proceedings of the ACM on Software Engineering}%
  \def\@journalNameShort{Proc. ACM Softw. Eng.}%
  \def\@permissionCodeOne{2994-970X}%
  \@ACM@screentrue
  \PackageInfo{\@classname}{Using screen mode due to \@journalCode}%
\or % POMACS
  \def\@journalName{Proceedings of the ACM on Measurement and Analysis of Computing Systems}%
  \def\@journalNameShort{Proc. ACM Meas. Anal. Comput. Syst.}%
  \def\@permissionCodeOne{2476-1249}%
  \@ACM@screentrue
  \PackageInfo{\@classname}{Using screen mode due to \@journalCode}%
\or % TAAS
  \def\@journalName{ACM Transactions on Autonomous and Adaptive Systems}%
  \def\@journalNameShort{ACM Trans. Autonom. Adapt. Syst.}%
  \def\@permissionCodeOne{1556-4665}%
\or % TACCESS
  \def\@journalName{ACM Transactions on Accessible Computing}%
  \def\@journalNameShort{ACM Trans. Access. Comput.}%
  \def\@permissionCodeOne{1936-7228}%
\or % TACO
  \def\@journalName{ACM Transactions on Architecture and Code Optimization}%
  \def\@journalNameShort{ACM Trans. Arch. Code Optim.}%
  \def\@permissionCodeOne{1544-3566}%
  \def\@permissionCodeTwo{1544-3973}%
\or % TALG
  \def\@journalName{ACM Transactions on Algorithms}%
  \def\@journalNameShort{ACM Trans. Algor.}%
  \def\@permissionCodeOne{1549-6325}%
\or % TALLIP
  \def\@journalName{ACM Transactions on Asian and Low-Resource Language Information Processing}%
  \def\@journalNameShort{ACM Trans. Asian Low-Resour. Lang. Inf. Process.}%
  \def\@permissionCodeOne{2375-4699}%
\or % TAP
  \def\@journalName{ACM Transactions on Applied Perception}%
  \def\@journalNameShort{ACM Trans. Appl. Percept.}%
  \def\@permissionCodeOne{1544-3558}%
\or % TCPS
  \def\@journalName{ACM Transactions on Cyber-Physical Systems}%
  \def\@journalNameShort{ACM Trans. Cyber-Phys. Syst.}%
  \def\@permissionCodeOne{2378-962X}%
\or % TDS
  \def\@journalName{ACM/IMS Transactions on Data Science}%
  \def\@journalNameShort{ACM/IMS Trans. Data Sci.}%
  \def\@permissionCodeOne{2577-3224}%
\or % TEAC
  \def\@journalName{ACM Transactions on Economics and Computation}%
  \def\@journalNameShort{ACM Trans. Econ. Comput.}%
  \def\@permissionCodeOne{2167-8375}%
\or % TECS
  \def\@journalName{ACM Transactions on Embedded Computing Systems}%
  \def\@journalNameShort{ACM Trans. Embedd. Comput. Syst.}%
  \def\@permissionCodeOne{1539-9087}%
\or % TELO
  \def\@journalName{ACM Transactions on Evolutionary Learning}%
  \def\@journalNameShort{ACM Trans. Evol. Learn.}%
  \def\@permissionCodeOne{2688-3007}%
\or % THRI
  \def\@journalName{ACM Transactions on Human-Robot Interaction}%
  \def\@journalNameShort{ACM Trans. Hum.-Robot Interact.}%
  \def\@permissionCodeOne{2573-9522}%
\or % TIIS
  \def\@journalName{ACM Transactions on Interactive Intelligent Systems}%
  \def\@journalNameShort{ACM Trans. Interact. Intell. Syst.}%
  \def\@permissionCodeOne{2160-6455}%
\or % TIOT
  \def\@journalName{ACM Transactions on Internet of Things}%
  \def\@journalNameShort{ACM Trans. Internet Things}%
  \def\@permissionCodeOne{2577-6207}%
\or % TISSEC
  \def\@journalName{ACM Transactions on Information and System Security}%
  \def\@journalNameShort{ACM Trans. Info. Syst. Sec.}%
  \def\@permissionCodeOne{1094-9224}%
\or % TIST
  \def\@journalName{ACM Transactions on Intelligent Systems and Technology}%
  \def\@journalNameShort{ACM Trans. Intell. Syst. Technol.}%
  \def\@permissionCodeOne{2157-6904}%
\or % TKDD
  \def\@journalName{ACM Transactions on Knowledge Discovery from Data}%
  \def\@journalNameShort{ACM Trans. Knowl. Discov. Data.}%
  \def\@permissionCodeOne{1556-4681}%
\or % TMIS
  \def\@journalName{ACM Transactions on Management Information Systems}%
  \def\@journalNameShort{ACM Trans. Manag. Inform. Syst.}%
  \def\@permissionCodeOne{2158-656X}%
\or % TOCE
  \def\@journalName{ACM Transactions on Computing Education}%
  \def\@journalNameShort{ACM Trans. Comput. Educ.}%
  \def\@permissionCodeOne{1946-6226}%
\or % TOCHI
  \def\@journalName{ACM Transactions on Computer-Human Interaction}%
  \def\@journalNameShort{ACM Trans. Comput.-Hum. Interact.}%
  \def\@permissionCodeOne{1073-0516}%
\or % TOCL
  \def\@journalName{ACM Transactions on Computational Logic}%
  \def\@journalNameShort{ACM Trans. Comput. Logic}%
  \def\@permissionCodeOne{1529-3785}%
\or % TOCS
  \def\@journalName{ACM Transactions on Computer Systems}%
  \def\@journalNameShort{ACM Trans. Comput. Syst.}%
  \def\@permissionCodeOne{0734-2071}%
\or % TOCT
  \def\@journalName{ACM Transactions on Computation Theory}%
  \def\@journalNameShort{ACM Trans. Comput. Theory}%
  \def\@permissionCodeOne{1942-3454}%
\or % TODAES
  \def\@journalName{ACM Transactions on Design Automation of Electronic Systems}%
  \def\@journalNameShort{ACM Trans. Des. Autom. Electron. Syst.}%
  \def\@permissionCodeOne{1084-4309}%
\or % TODS
  \def\@journalName{ACM Transactions on Database Systems}%
  \def\@journalNameShort{ACM Trans. Datab. Syst.}%
  \def\@permissionCodeOne{0362-5915}%
\or % TOG
  \def\@journalName{ACM Transactions on Graphics}%
  \def\@journalNameShort{ACM Trans. Graph.}%
  \def\@permissionCodeOne{0730-0301}
\or % TOIS
  \def\@journalName{ACM Transactions on Information Systems}%
  \def\@journalNameShort{ACM Trans. Inf. Syst.}%
  \def\@permissionCodeOne{1046-8188}%
\or % TOIT
  \def\@journalName{ACM Transactions on Internet Technology}%
  \def\@journalNameShort{ACM Trans. Internet Technol.}%
  \def\@permissionCodeOne{1533-5399}%
\or % TOMACS
  \def\@journalName{ACM Transactions on Modeling and Computer Simulation}%
  \def\@journalNameShort{ACM Trans. Model. Comput. Simul.}%
  \def\@permissionCodeOne{1049-3301}%
  \def\@permissionCodeTwo{1558-1195}%
\or % TOMM
  \def\@journalName{ACM Transactions on Multimedia Computing, Communications and Applications}%
  \def\@journalNameShort{ACM Trans. Multimedia Comput. Commun. Appl.}%
  \def\@permissionCodeOne{1551-6857}%
  \def\@permissionCodeTwo{1551-6865}%
\or % TOMPECS
  \def\@journalName{ACM Transactions on Modeling and Performance Evaluation of Computing Systems}%
  \def\@journalNameShort{ACM Trans. Model. Perform. Eval. Comput. Syst.}%
  \def\@permissionCodeOne{2376-3639}%
\or % TOMS
  \def\@journalName{ACM Transactions on Mathematical Software}%
  \def\@journalNameShort{ACM Trans. Math. Softw.}%
  \def\@permissionCodeOne{0098-3500}%
\or % TOPC
  \def\@journalName{ACM Transactions on Parallel Computing}%
  \def\@journalNameShort{ACM Trans. Parallel Comput.}%
  \def\@permissionCodeOne{2329-4949}%
  \def\@permissionCodeTwo{2329-4957}%
\or % TOPS
  \def\@journalName{ACM Transactions on Privacy and Security}%
  \def\@journalNameShort{ACM Trans. Priv. Sec.}%
  \def\@permissionCodeOne{2471-2566}%
\or % TOPLAS
  \def\@journalName{ACM Transactions on Programming Languages and Systems}%
  \def\@journalNameShort{ACM Trans. Program. Lang. Syst.}%
  \def\@permissionCodeOne{0164-0925}%
\or % TOPML
  \def\@journalName{ACM Transactions on Probabilistic Machine Learning}%
  \def\@journalNameShort{ACM Trans. Probab. Mach. Learn.}%
  \def\@permissionCodeOne{2836-8924}%
\or % TORS
  \def\@journalName{ACM Transactions on Recommender Systems}%
  \def\@journalNameShort{ACM Trans. Recomm. Syst.}%
  \def\@permissionCodeOne{2770-6699}%
\or % TOS
  \def\@journalName{ACM Transactions on Storage}%
  \def\@journalNameShort{ACM Trans. Storage}%
  \def\@permissionCodeOne{1553-3077}%
\or % TOSEM
  \def\@journalName{ACM Transactions on Software Engineering and Methodology}%
  \def\@journalNameShort{ACM Trans. Softw. Eng. Methodol.}%
  \def\@permissionCodeOne{1049-331X}%
\or % TOSN
  \def\@journalName{ACM Transactions on Sensor Networks}%
  \def\@journalNameShort{ACM Trans. Sensor Netw.}%
  \def\@permissionCodeOne{1550-4859}%
\or % TQC
  \def\@journalName{ACM Transactions on Quantum Computing}%
  \def\@journalNameShort{ACM Trans. Quantum Comput.}%
  \def\@permissionCodeOne{2643-6817}%
\or % TRETS
  \def\@journalName{ACM Transactions on Reconfigurable Technology and Systems}%
  \def\@journalNameShort{ACM Trans. Reconfig. Technol. Syst.}%
  \def\@permissionCodeOne{1936-7406}%
\or % TSAS
  \def\@journalName{ACM Transactions on Spatial Algorithms and Systems}%
  \def\@journalNameShort{ACM Trans. Spatial Algorithms Syst.}%
  \def\@permissionCodeOne{2374-0353}%
\or % TSC
  \def\@journalName{ACM Transactions on Social Computing}%
  \def\@journalNameShort{ACM Trans. Soc. Comput.}%
  \def\@permissionCodeOne{2469-7818}%
\or % TSLP
  \def\@journalName{ACM Transactions on Speech and Language Processing}%
  \def\@journalNameShort{ACM Trans. Speech Lang. Process.}%
  \def\@permissionCodeOne{1550-4875}%
\or % TWEB
  \def\@journalName{ACM Transactions on the Web}%
  \def\@journalNameShort{ACM Trans. Web}%
  \def\@permissionCodeOne{1559-1131}%
\else % FACMP, a dummy journal
  \def\@journalName{ACM Just Accepted}%
  \def\@journalNameShort{ACM Accepted}%
  \def\@permissionCodeOne{XXXX-XXXX}%
\fi
\ClassInfo{\@classname}{Using journal code \@journalCode}%
}{%
  \ClassError{\@classname}{Incorrect journal #1}%
}%
\def\acmJournal#1{\setkeys{ACM}{acmJournal=#1}%
  \global\@ACM@journal@bibstriptrue}
\def\@journalCode@nr{0}
\def\@journalName{}%
\def\@journalNameShort{\@journalName}%
\def\@permissionCodeOne{XXXX-XXXX}%
\def\@permissionCodeTwo{}%
\newcommand\acmConference[4][]{%
  \gdef\acmConference@shortname{#1}%
  \gdef\acmConference@name{#2}%
  \gdef\acmConference@date{#3}%
  \gdef\acmConference@venue{#4}%
  \ifx\acmConference@shortname\@empty
    \gdef\acmConference@shortname{#2}%
  \fi
  \global\@ACM@journal@bibstripfalse
}
\if@ACM@journal\else
\acmConference[Conference'17]{ACM Conference}{July 2017}{Washington,
  DC, USA}%
\fi
\def\acmBooktitle#1{\gdef\@acmBooktitle{#1}}
\acmBooktitle{}
\ifx\acmConference@name\@undefined\else
\acmBooktitle{Proceedings of \acmConference@name
       \ifx\acmConference@name\acmConference@shortname\else
       \ (\acmConference@shortname)\fi}
\fi
\def\@editorsAbbrev{(Ed.)}
\def\@acmEditors{}
\def\editor#1{\ifx\@acmEditors\@empty
    \gdef\@acmEditors{#1}%
  \else
    \gdef\@editorsAbbrev{(Eds.)}%
    \g@addto@macro\@acmEditors{\and#1}%
\fi}
\def\subtitle#1{\def\@subtitle{#1}}
\subtitle{}
\newcount\num@authorgroups
\num@authorgroups=0\relax
\newcount\num@authors
\num@authors=0\relax
\newif\if@insideauthorgroup
\@insideauthorgroupfalse
\renewcommand\author[2][]{%
  \IfSubStr{\detokenize{#2}}{,}{\ClassWarning{\@classname}{Do not put several
      authors in the same \string\author\space macro!}}{}%
  \global\advance\num@authors by 1\relax
  \if@insideauthorgroup\else
    \global\advance\num@authorgroups by 1\relax
    \global\@insideauthorgrouptrue
  \fi
  \ifx\addresses\@empty
    \if@ACM@anonymous
      \gdef\addresses{\@author{Anonymous Author(s)%
        \ifx\@acmSubmissionID\@empty\else\\Submission Id:
          \@acmSubmissionID\fi}}%
      \gdef\authors{Anonymous Author(s)}%
    \else
      \expandafter\gdef\expandafter\addresses\expandafter{%
        \expandafter\@author\expandafter{%
          \csname typeset@author\the\num@authors\endcsname{#2}}}%
      \gdef\authors{#2}%
    \fi
  \else
    \if@ACM@anonymous\else
    \expandafter\g@addto@macro\expandafter\addresses\expandafter{%
      \expandafter\and\expandafter\@author\expandafter{%
        \csname typeset@author\the\num@authors\endcsname{#2}}}%
      \g@addto@macro\authors{\and#2}%
    \fi
  \fi
  \if@ACM@anonymous
    \ifx\shortauthors\@empty
      \gdef\shortauthors{Anon.
        \ifx\@acmSubmissionID\@empty\else Submission Id:
        \@acmSubmissionID\fi}%
    \fi
  \else
    \def\@tempa{#1}%
    \ifx\@tempa\@empty
      \ifx\shortauthors\@empty
        \gdef\shortauthors{#2}%
      \else
        \g@addto@macro\shortauthors{\and#2}%
      \fi
    \else
      \ifx\shortauthors\@empty
        \gdef\shortauthors{#1}%
      \else
        \g@addto@macro\shortauthors{\and#1}%
      \fi
    \fi
  \fi}
\newcommand{\affiliation}[2][]{%
  \global\@insideauthorgroupfalse
  \if@ACM@anonymous\else
    \g@addto@macro\addresses{\affiliation{#1}{#2}}%
  \fi}
\define@boolkey+{@ACM@affiliation@}[@ACM@affiliation@]{obeypunctuation}%
[true]{}{\ClassError{\@classname}{The option obeypunctuation can be either true or false}}
\def\additionalaffiliation#1{\authornote{\@additionalaffiliation{#1}}}
\def\@additionalaffiliation#1{\bgroup
  \def\position##1{\ignorespaces}%
  \def\institution##1{##1\ignorespaces}%
  \def\department{\@ifnextchar[{\@department}{\@department[]}}%
  \def\@department[##1]##2{\unskip, ##2\ignorespaces}%
  \let\streetaddress\position
  \let\city\position
  \let\state\position
  \let\postcode\position
  \let\country\position
  Also with #1\unskip.\egroup}
\renewcommand{\email}[2][]{%
  \IfSubStr{#2}{,}{\ClassWarning{\@classname}{Do not put several
      addresses in the same \string\email\space macro!}}{}%
  \if@ACM@anonymous\else
    \g@addto@macro\addresses{\email{#1}{#2}}%
  \fi}
\def\orcid#1{\unskip\ignorespaces%
  \IfBeginWith{#1}{http}{%
    \expandafter\gdef\csname
        typeset@author\the\num@authors\endcsname##1{%
          \href{#1}{##1}}}{%
    \expandafter\gdef\csname
        typeset@author\the\num@authors\endcsname##1{%
          \href{https://orcid.org/#1}{##1}}}}
\def\authorsaddresses#1{\def\@authorsaddresses{#1}}
\authorsaddresses{\@mkauthorsaddresses}
\newcommand\@mktranslatedkeywords[2]{\bgroup
  \selectlanguage{#1}%
  {\@specialsection{\keywordsname}%
    \noindent#2\par}\egroup}
\def\@titlenotes{}
\def\titlenote#1{%
  \g@addto@macro\@title{\footnotemark}%
  \if@ACM@anonymous
    \g@addto@macro\@titlenotes{%
      \stepcounter{footnote}\footnotetext{Title note}}%
  \else
    \g@addto@macro\@titlenotes{\stepcounter{footnote}\footnotetext{#1}}%
  \fi}
\def\@subtitlenotes{}
\def\subtitlenote#1{%
  \g@addto@macro\@subtitle{\footnotemark}%
  \if@ACM@anonymous
    \g@addto@macro\@subtitlenotes{%
      \stepcounter{footnote}\footnotetext{Subtitle note}}%
  \else
    \g@addto@macro\@subtitlenotes{%
      \stepcounter{footnote}\footnotetext{#1}}%
  \fi}
\def\@authornotes{}
\def\authornote#1{%
  \if@ACM@anonymous\else
    \g@addto@macro\addresses{\@authornotemark}%
    \g@addto@macro\@authornotes{%
      \stepcounter{footnote}\footnotetext{#1}}%
  \fi}
\newcommand\authornotemark[1][\relax]{%
  \ifx#1\relax\relax\relax
  \g@addto@macro\addresses{\@authornotemark}%
  \else
  \g@addto@macro\addresses{\@@authornotemark{#1}}%
  \fi}
\def\acmVolume#1{\def\@acmVolume{#1}}
\acmVolume{1}
\def\acmNumber#1{\def\@acmNumber{#1}}
\acmNumber{1}
\def\acmArticle#1{\def\@acmArticle{#1}}
\acmArticle{}
\def\acmArticleSeq#1{\def\@acmArticleSeq{#1}}
\acmArticleSeq{\@acmArticle}
\def\acmYear#1{\def\@acmYear{#1}}
\acmYear{\the\year}
\def\acmMonth#1{\def\@acmMonth{#1}}
\acmMonth{\the\month}
\def\@acmPubDate{\ifcase\@acmMonth\or
  January\or February\or March\or April\or May\or June\or
  July\or August\or September\or October\or November\or
  December\fi~\@acmYear}
\def\acmPrice#1{\ClassWarning{\@classname}{The macro \string\acmPrice
    is obsolete.  ACM no longer prints the price in bibstrip.}}
\def\acmSubmissionID#1{\def\@acmSubmissionID{#1}}
\acmSubmissionID{}
\def\acmISBN#1{\def\@acmISBN{#1}}
\acmISBN{978-x-xxxx-xxxx-x/YY/MM}
\def\acmDOI#1{\def\@acmDOI{#1}}
\acmDOI{10.1145/nnnnnnn.nnnnnnn}
\newlength\@ACM@badge@width
\setlength\@ACM@badge@width{3pc}
\newlength\@ACM@title@width
\newlength\@ACM@badge@skip
\setlength\@ACM@badge@skip{1pt}
\def\@acmBadgeR{}
\def\@acmBadgeL{}
\newcommand\acmBadgeR[2][]{%
  \ifx\@acmBadgeR\@empty
    \gdef\@acmBadgeR{%
      \smash{%
        \raisebox{0.5\height}{%
          \href{#1}{\includegraphics[width=\@ACM@badge@width]{#2}}}}}%
  \else
    \g@addto@macro{\@acmBadgeR}{%
      \hspace{\@ACM@badge@skip}%
      \smash{%
        \raisebox{0.5\height}{%
          \href{#1}{\includegraphics[width=\@ACM@badge@width]{#2}}}}}%
  \fi}
\newcommand\acmBadgeL[2][]{%
  \ifx\@acmBadgeL\@empty
    \gdef\@acmBadgeL{%
      \smash{%
        \raisebox{0.5\height}{%
          \href{#1}{\includegraphics[width=\@ACM@badge@width]{#2}}}}}%
  \else
    \g@addto@macro{\@acmBadgeL}{%
      \hspace{\@ACM@badge@skip}%
      \smash{%
        \raisebox{0.5\height}{%
          \href{#1}{\includegraphics[width=\@ACM@badge@width]{#2}}}}}%
  \fi}
\let\acmBadge=\acmBadgeR
\def\startPage#1{\def\@startPage{#1}}
\startPage{}
\def\terms#1{\ClassWarning{\@classname}{The command \string\terms{} is
    obsolete.  I am going to ignore it}}
\def\keywords#1{\def\@keywords{#1}}
\let\@keywords\@empty
\AtEndDocument{\if@ACM@nonacm\else\ifx\@keywords\@empty
  \ifnum\getrefnumber{TotPages}>2\relax
  \ClassWarningNoLine{\@classname}{ACM keywords are mandatory
    for papers over two pages}%
  \fi\fi\fi}
\renewenvironment{abstract}{\Collect@Body\@saveabstract}{}
\long\def\@saveabstract#1{\if@ACM@maketitle@typeset
  \ClassError{\@classname}{Abstract must be defined before maketitle
    command. Please move it!}\fi
  \long\gdef\@abstract{#1}}
\@saveabstract{}
\long\def\@lempty{}
\define@boolkey+{@ACM@topmatter@}[@ACM@]{printccs}[true]{%
  \if@ACM@printccs
    \ClassInfo{\@classname}{Printing CCS}%
  \else
    \ClassInfo{\@classname}{Suppressing CCS}%
  \fi}{\ClassError{\@classname}{The option printccs can be either true or false}}
\define@boolkey+{@ACM@topmatter@}[@ACM@]{printacmref}[true]{%
  \if@ACM@printacmref
    \ClassInfo{\@classname}{Printing bibformat}%
  \else
    \ClassInfo{\@classname}{Suppressing bibformat}%
  \fi}{\ClassError{\@classname}{The option printacmref can be either true or false}}
\AtEndDocument{\if@ACM@nonacm\else\if@ACM@printacmref\else
  \ifnum\getrefnumber{TotPages}>1\relax
  \ClassWarningNoLine{\@classname}{%
    ACM reference format is mandatory \MessageBreak
    for papers over one page. \MessageBreak
    Please add printacmref=true to the \MessageBreak
    \string\settopmatter\space command.}%
  \fi\fi\fi}
\define@boolkey+{@ACM@topmatter@}[@ACM@]{printfolios}[true]{%
  \if@ACM@printfolios
    \ClassInfo{\@classname}{Printing folios}%
  \else
    \ClassInfo{\@classname}{Suppressing folios}%
  \fi}{\ClassError{\@classname}{The option printfolios can be either true or false}}
\define@cmdkey{@ACM@topmatter@}[@ACM@]{authorsperrow}[0]{%
  \IfInteger{#1}{\ClassInfo{\@classname}{Setting authorsperrow to
      #1}}{\ClassWarning{\@classname}{The parameter authorsperrow must be
      numerical. Ignoring the input #1}\gdef\@ACM@authorsperrow{0}}}
\def\settopmatter#1{\setkeys{@ACM@topmatter@}{#1}}
\settopmatter{printccs=true, printacmref=true}
\if@ACM@manuscript
  \settopmatter{printfolios=true}
\else
  \if@ACM@journal
    \settopmatter{printfolios=true}
  \else
    \settopmatter{printfolios=false}
  \fi
\fi
\settopmatter{authorsperrow=0}
\def\@received{}
\newcommand\received[2][]{\def\@tempa{#1}%
  \ifx\@tempa\@empty
    \ifx\@received\@empty
      \gdef\@received{Received #2}%
    \else
      \g@addto@macro{\@received}{; revised #2}%
    \fi
  \else
    \ifx\@received\@empty
      \gdef\@received{#1 #2}%
    \else
      \g@addto@macro{\@received}{; #1 #2}%
    \fi
  \fi}
\AtEndDocument{%
  \ifx\@received\@empty\else
    \par\bigskip\noindent\small\normalfont\@received\par
  \fi}
\define@choicekey+{ACM}{articletype}[\ACM@ArticleType\ACM@ArticleType@nr]{%
  Research,Review,Discussion,Invited,Position}[Review]{%
  \ifcase\ACM@ArticleType@nr
  \relax % Research
     \colorlet{@ACM@Article@color}{ACMBlue}%
  \or % Review
     \colorlet{@ACM@Article@color}{ACMOrange}%
  \or % Discussion
     \colorlet{@ACM@Article@color}{ACMGreen}%
  \or % Invited
     \colorlet{@ACM@Article@color}{ACMPurple}%
  \or % Position
     \colorlet{@ACM@Article@color}{ACMRed}%
  \fi
}{%
 \ClassError{\@classname}{Article Type must be Research, Review,\MessageBreak
   Discussion, Invited, or Position}}
\def\acmArticleType#1{\setkeys{ACM}{articletype=#1}}
\if@ACM@acmcp
\acmArticleType{Research}%
\fi
 %    \end{macrocode}
\newenvironment{@ACM@color@frame}{%
  \def\FrameCommand{\hspace*{-6.5pc}%
    \colorbox{@ACM@Article@color!10!white}}%
  \MakeFramed {\advance\hsize
    -6.5pc\relax\FrameRestore}}{\zsaveposy{@ACM@acmcpframe@y}%
  \endMakeFramed}
\def\acmCodeLink#1{%
  \ifx\@acmCodeDataLink\@empty
     \gdef\@acmCodeDataLink{\url{#1}}%
  \else
     \g@addto@macro{\@acmCodeDataLink}{\\ \url{#1}}%
  \fi}
\def\@acmCodeDataLink{}
\def\acmContributions#1{\gdef\@acmContributions{#1}}
\acmContributions{}
\let\acmDataLink\acmCodeLink
\RequirePackage{comment}
\excludecomment{CCSXML}
\let\@concepts\@empty
\newcounter{@concepts}
\newcommand\ccsdesc[2][100]{%
  \ccsdesc@parse#1~#2~~\ccsdesc@parse@end}
\def\textrightarrow{$\rightarrow$}
\def\ccsdesc@parse#1~#2~#3~{%
  \stepcounter{@concepts}%
  \expandafter\ifx\csname CCS@General@#2\endcsname\relax
    \expandafter\gdef\csname CCS@General@#2\endcsname{\textbullet\
      \textbf{#2}}%
    \expandafter\gdef\csname CCS@Punctuation@#2\endcsname{; }%
    \expandafter\gdef\csname CCS@Specific@#2\endcsname{}%
  \g@addto@macro{\@concepts}{\csname CCS@General@#2\endcsname
    \csname CCS@Punctuation@#2\endcsname
    \csname CCS@Specific@#2\endcsname}%
  \fi
  \ifx#3\relax\relax\else
    \expandafter\gdef\csname CCS@Punctuation@#2\endcsname{
      \textrightarrow\ }%
    \expandafter\g@addto@macro\expandafter{\csname CCS@Specific@#2\endcsname}{%
     \addtocounter{@concepts}{-1}%
     \ifnum#1>499\textbf{#3}\else
     \ifnum#1>299\textit{#3}\else
     #3\fi\fi\ifnum\value{@concepts}=0.\else; \fi}%
  \fi
\ccsdesc@parse@finish}
\AtEndDocument{\if@ACM@nonacm\else\ifx\@concepts\@empty\relax
  \ifnum\getrefnumber{TotPages}>2\relax
  \ClassWarningNoLine{\@classname}{CCS concepts are mandatory
    for papers over two pages}%
  \fi\fi\fi}
\def\ccsdesc@parse@finish#1\ccsdesc@parse@end{}
\newif\if@printcopyright
\@printcopyrighttrue
\newif\if@printpermission
\@printpermissiontrue
\newif\if@acmowned
\@acmownedtrue
\define@choicekey*{ACM@}{acmcopyrightmode}[%
  \acm@copyrightinput\acm@copyrightmode]{none,%
    acmcopyright,acmlicensed,rightsretained,%
    usgov,usgovmixed,cagov,cagovmixed,licensedusgovmixed,%
    licensedcagov,licensedcagovmixed,othergov,licensedothergov,%
    iw3c2w3,iw3c2w3g,cc}{%
  \@printpermissiontrue
  \@printcopyrighttrue
  \@acmownedtrue
  \ifnum\acm@copyrightmode=0\relax % none
   \@printpermissionfalse
   \@printcopyrightfalse
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=2\relax % acmlicensed
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=3\relax % rightsretained
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=4\relax % usgov
   \@printpermissiontrue
   \@printcopyrightfalse
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=6\relax % cagov
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=8\relax % licensedusgovmixed
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=9\relax % licensedcagov
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=10\relax % licensedcagovmixed
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=11\relax % othergov
   \@acmownedtrue
  \fi
  \ifnum\acm@copyrightmode=12\relax % licensedothergov
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=13\relax % iw3c2w3
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=14\relax % iw3c2w3g
   \@acmownedfalse
  \fi
  \ifnum\acm@copyrightmode=15\relax % cc
   \@acmownedfalse
  \fi}
\def\setcopyright#1{\setkeys{ACM@}{acmcopyrightmode=#1}}
\setcopyright{acmlicensed}
\newcommand\setcctype[2][4.0]{%
  \def\ACM@cc@version{#1}%
  \def\ACM@cc@type{#2}}
\setcctype{by}
\def\@copyrightowner{%
  \ifcase\acm@copyrightmode\relax % none
  \or % acmcopyright
  ACM\@.
  \or % acmlicensed
  Copyright held by the owner/author(s). Publication rights licensed to
  ACM\@.
  \or % rightsretained
  Copyright held by the owner/author(s).
  \or % usgov
  \or % usgovmixed
  Copyright held by the owner/author(s).
  \or % cagov
  Copyright Crown in Right of Canada.
  \or %cagovmixed
  Copyright held by the owner/author(s).
  \or %licensedusgovmixed
  Copyright held by the owner/author(s). Publication rights licensed to
  ACM\@.
  \or % licensedcagov
  Copyright held by the owner/author(s).
  \or %licensedcagovmixed
  Copyright held by the owner/author(s). Publication rights licensed to
  ACM\@.
  \or % othergov
  Copyright held by the owner/author(s).
  \or % licensedothergov
  Copyright held by the owner/author(s). Publication rights licensed to
  ACM\@.
  \or % ic2w3www
  IW3C2 (International World Wide Web Conference Committee), published
  under Creative Commons CC-BY~4.0 License.
  \or % ic2w3wwwgoogle
  IW3C2 (International World Wide Web Conference Committee), published
  under Creative Commons CC-BY-NC-ND~4.0 License.
  \or % cc
  Copyright held by the owner/author(s).
  \fi}
\def\@formatdoi#1{\url{https://doi.org/#1}}
\def\@ACM@copyright@check@cc{%
  \if@ACM@nonacm
     \ClassInfo{\@classname}{Using CC license with a non-acm
       material}%
  \else
     \if@ACM@engage
        \ClassInfo{\@classname}{Using CC license with ACM Enage
          material}%
      \else
      \ClassWarning{\@classname}{%
        Sorry, Creative Commons licenses are\MessageBreak
        currently not used with ACM publications\MessageBreak
        typeset by the authors}{Please use nonacm
           option or ACM Engage class to enable CC licenses}%
      \fi
  \fi}
\def\@copyrightpermission{%
  \ifcase\acm@copyrightmode\relax % none
  \or % acmcopyright
   Permission to make digital or hard copies of all or part of this
   work for personal or classroom use is granted without fee provided
   that copies are not made or distributed for profit or commercial
   advantage and that copies bear this notice and the full citation on
   the first page. Copyrights for components of this work owned by
   others than ACM must be honored. Abstracting with credit is
   permitted. To copy otherwise, or republish, to post on servers or
   to redistribute to lists, requires prior specific permission
   and\hspace*{.5pt}/or
   a fee. Request permissions from permissions@acm.org.
  \or % acmlicensed
   Permission to make digital or hard copies of all or part of this
   work for personal or classroom use is granted without fee provided
   that copies are not made or distributed for profit or commercial
   advantage and that copies bear this notice and the full citation on
   the first page. Copyrights for components of this work owned by
   others than the author(s) must be honored. Abstracting with credit
   is permitted. To copy otherwise, or republish, to post on servers
   or to redistribute to lists, requires prior specific permission
   and\hspace*{.5pt}/or a fee. Request permissions from
   permissions@acm.org.
  \or % rightsretained
   Permission to make digital or hard copies of part or all of this
   work for personal or classroom use is granted without fee provided
   that copies are not made or distributed for profit or commercial
   advantage and that copies bear this notice and the full citation on
   the first page. Copyrights for third-party components of this work
   must be honored. For all other uses, contact the
   owner\hspace*{.5pt}/author(s).
  \or % usgov
   This paper is authored by an employee(s) of the United States
   Government and is in the public domain. Non-exclusive copying or
   redistribution is allowed, provided that the article citation is
   given and the authors and agency are clearly identified as its
   source. All others Request permissions from
   owner\hspace*{.5pt}/author(s).
  \or % usgovmixed
   ACM acknowledges that this contribution was authored or co-authored
   by an employee, contractor, or affiliate of the United States
   government. As such, the United States government retains a
   nonexclusive, royalty-free right to publish or reproduce this
   article, or to allow others to do so, for government purposes
   only. Request permissions from owner\hspace*{.5pt}/author(s).
  \or % cagov
   This article was authored by employees of the Government of
   Canada. As such, the Canadian government retains all interest in
   the copyright to this work and grants to ACM a nonexclusive,
   royalty-free right to publish or reproduce this article, or to
   allow others to do so, provided that clear attribution is given
   both to the authors and the Canadian government agency employing
   them. Permission to make digital or hard copies for personal or
   classroom use is granted. Copies must bear this notice and the full
   citation on the first page. Copyrights for components of this work
   owned by others than the Canadian Government must be honored. To
   copy otherwise, distribute, republish, or post, requires prior
   specific permission and/or a fee. Request permissions from
   owner\hspace*{.5pt}/author(s).
  \or % cagovmixed
   ACM acknowledges that this contribution was co-authored by an
   affiliate of the national government of Canada. As such, the Crown
   in Right of Canada retains an equal interest in the
   copyright. Reprints must include clear attribution to ACM and the
   author’s government agency affiliation. Permission to make digital
   or hard copies for personal or classroom use is granted. Copies
   must bear this notice and the full citation on the first
   page. Copyrights for components of this work owned by others than
   ACM must be honored. To copy otherwise, distribute, republish, or
   post, requires prior specific permission and/or a fee. Request
   permissions from owner\hspace*{.5pt}/author(s).
  \or % licensedusgovmixed
   Publication rights licensed to ACM\@. ACM acknowledges that this
   contribution was authored or co-authored by an employee, contractor
   or affiliate of the United States government. As such, the
   Government retains a nonexclusive, royalty-free right to publish or
   reproduce this article, or to allow others to do so, for Government
   purposes only. Request permissions from
   owner\hspace*{.5pt}/author(s).
  \or % licensedcagov
   This article was authored by employees of the Government of
   Canada. As such, the Canadian government retains all interest in
   the copyright to this work and grants to ACM a nonexclusive,
   royalty-free right to publish or reproduce this article, or to
   allow others to do so, provided that clear attribution is given
   both to the authors and the Canadian government agency employing
   them. Permission to make digital or hard copies for personal or
   classroom use is granted. Copies must bear this notice and the full
   citation on the first page. Copyrights for components of this work
   owned by others than the Canadian Government must be honored. To
   copy otherwise, distribute, republish, or post, requires prior
   specific permission and/or a fee. Request permissions from
   owner\hspace*{.5pt}/author(s).
  \or % licensedcagovmixed
   Publication rights licensed to ACM. ACM acknowledges that this
   contribution was authored or co-authored by an employee, contractor
   or affiliate of the national government of Canada. As such, the
   Government retains a nonexclusive, royalty-free right to publish or
   reproduce this article, or to allow others to do so, for Government
   purposes only. Request permissions from
   owner\hspace*{.5pt}/author(s).
  \or % othergov
   ACM acknowledges that this contribution was authored or co-authored
   by an employee, contractor or affiliate of a national
   government. As such, the Government retains a nonexclusive,
   royalty-free right to publish or reproduce this article, or to
   allow others to do so, for Government purposes only. Request
   permissions from owner\hspace*{.5pt}/author(s).
  \or % licensedothergov
   Publication rights licensed to ACM\@. ACM acknowledges that this
   contribution was authored or co-authored by an employee, contractor
   or affiliate of a national government. As such, the Government
   retains a nonexclusive, royalty-free right to publish or reproduce
   this article, or to allow others to do so, for Government purposes
   only. Request permissions from owner\hspace*{.5pt}/author(s).
 \or % iw3c2w3
   This paper is published under the Creative Commons Attribution~4.0
   International (CC-BY~4.0) license. Authors reserve their rights to
   disseminate the work on their personal and corporate Web sites with
   the appropriate attribution.
 \or % iw3c2w3g
   This paper is published under the Creative Commons
   Attribution-NonCommercial-NoDerivs~4.0 International
   (CC-BY-NC-ND~4.0) license. Authors reserve their rights to
   disseminate the work on their personal and corporate Web sites with
   the appropriate attribution.
 \or % CC
   \@ACM@copyright@check@cc
   \IfEq{\ACM@cc@type}{zero}{%
     \def\ACM@CC@Url{https://creativecommons.org/publicdomain/zero/1.0/legalcode}}{%
  \edef\ACM@CC@Url{https://creativecommons.org/licenses/\ACM@cc@type/\ACM@cc@version/legalcode}}%
   \href{\ACM@CC@Url}{\includegraphics[height=5ex]{doclicense-CC-\ACM@cc@type-88x31}}\\
   \href{\ACM@CC@Url}{%
   This work is licensed under a Creative Commons
   \IfEq{\ACM@cc@type}{zero}{CC0 1.0 Universal}{%
     \IfEq{\ACM@cc@type}{by}{Attribution}{}%
     \IfEq{\ACM@cc@type}{by-sa}{Attribution-ShareAlike}{}%
     \IfEq{\ACM@cc@type}{by-nd}{Attribution-NoDerivatives}{}%
     \IfEq{\ACM@cc@type}{by-nc}{Attribution-NonCommercial}{}%
     \IfEq{\ACM@cc@type}{by-nc-sa}{Attribution-NonCommercial-ShareAlike}{}%
     \IfEq{\ACM@cc@type}{by-nc-nd}{Attribution-NonCommercial-NoDerivatives}{}%
     ~\IfEq{\ACM@cc@version}{4.0}{4.0 International}{3.0 Unported}%
   }
   License.}%
 \fi}
%%
\def\copyrightyear#1{\def\@copyrightyear{#1}}
\copyrightyear{\@acmYear}
\def\@teaserfigures{}
\newenvironment{teaserfigure}{\Collect@Body\@saveteaser}{}
\long\def\@saveteaser#1{\g@addto@macro\@teaserfigures{\@teaser{#1}}}
\renewcommand{\thanks}[1]{%
  \@ifnotempty{#1}{%
    \if@ACM@anonymous
      \g@addto@macro\thankses{\thanks{A note}}%
   \else
    \g@addto@macro\thankses{\thanks{#1}}%
   \fi}}
\newcommand{\anon}[2][ANONYMIZED]{%
  \if@ACM@anonymous%
    {\color{ACMOrange}#1}%
  \else%
    #2%
  \fi}
\ifx\@beginmaketitlehook\@undefined
  \let\@beginmaketitlehook\@empty
\fi
\def\AtBeginMaketitle{\g@addto@macro\@beginmaketitlehook}
\def\@acmengagemetadata{}
\def\setengagemetadata#1#2{%
  \g@addto@macro{\@acmengagemetadata}{%
    \@setengagemetadata{#1}{#2}}}
\newbox\mktitle@bx
\def\maketitle{\@beginmaketitlehook
  \@ACM@maketitle@typesettrue
  \if@ACM@anonymous
    % Anonymize omission of \author-s
    \ifnum\num@authorgroups=0\author{}\fi
  \fi
  \begingroup
  \let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig
  \let\@footnotemark\@footnotemark@nolink
  \let\@footnotetext\@footnotetext@nolink
  \renewcommand\thefootnote{\@fnsymbol\c@footnote}%
  \hsize=\textwidth
  \def\@makefnmark{\hbox{\@textsuperscript{\@thefnmark}}}%
  \@mktitle\if@ACM@sigchiamode\else\@mkauthors\fi\@mkteasers
  \@printtopmatter
  \if@ACM@sigchiamode\@mkauthors\fi
  \setcounter{footnote}{0}%
  \def\@makefnmark{\hbox{\@textsuperscript{\normalfont\@thefnmark}}}%
  \@titlenotes
  \@subtitlenotes
  \@authornotes
  \let\@makefnmark\relax
  \let\@thefnmark\relax
  \let\@makefntext\noindent
  \ifx\@empty\thankses\else
    \footnotetextauthorsaddresses{%
      \def\par{\let\par\@par}\parindent\z@\@setthanks}%
  \fi
  \if@ACM@acmcp\else
    \ifx\@empty\@authorsaddresses\else
       \if@ACM@anonymous\else
         \if@ACM@journal@bibstrip
           \footnotetextauthorsaddresses{%
             \def\par{\let\par\@par}\parindent\z@\@setauthorsaddresses}%
         \fi
       \fi
    \fi
  \fi
  \if@ACM@nonacm
    \ifnum\acm@copyrightmode=15\relax % cc
       \footnotetextcopyrightpermission{\@copyrightpermission}%
    \fi
  \else
    \if@ACM@acmcp\else
    \footnotetextcopyrightpermission{%
    \if@ACM@authordraft
        \raisebox{-2ex}[\z@][\z@]{\makebox[0pt][l]{\large\bfseries
            Unpublished working draft. Not for distribution.}}%
       \color[gray]{0.9}%
    \fi
    \parindent\z@\parskip0.1\baselineskip
    \if@ACM@authorversion\else
      \if@printpermission\@copyrightpermission\par\fi
    \fi
    \if@ACM@manuscript\else
       \if@ACM@journal@bibstrip\else % Print the conference information
         \if@ACM@engage
            {\itshape \@acmBooktitle, \@acmYear.}\par
         \else
         {\itshape \acmConference@shortname, \acmConference@date, \acmConference@venue}\par
         \fi
       \fi
    \fi
    \if@printcopyright
      \copyright\ \@copyrightyear\ \@copyrightowner\\
    \else
      \@copyrightyear.\
    \fi
    \if@ACM@manuscript
      Manuscript submitted to ACM\\
    \else
      \if@ACM@authorversion
          This is the author's version of the work. It is posted here for
          your personal use. Not for redistribution. The definitive Version
          of Record was published in
          \if@ACM@journal@bibstrip
            \emph{\@journalName}%
          \else
            \emph{\@acmBooktitle}%
          \fi
          \ifx\@acmDOI\@empty
          .
          \else
            , \@formatdoi{\@acmDOI}.
          \fi\\
        \else
          \if@ACM@nonacm\else
            \if@ACM@journal@bibstrip
              ACM~\@permissionCodeOne/\@acmYear/\@acmMonth-ART\@acmArticle\\
              \@formatdoi{\@acmDOI}%
            \else % Conference
              \ifx\@acmISBN\@empty\else ACM~ISBN~\@acmISBN\\\fi
              \ifx\@acmDOI\@empty\else\@formatdoi{\@acmDOI}\fi%
            \fi
          \fi
        \fi
      \fi}%
    \fi
    \fi
  \endgroup
  \if@ACM@engage\@typesetengagemetadata\fi
  \setcounter{footnote}{0}%
  \@mkabstract
  \ifx\@translatedabstracts\@empty\else
  \@translatedabstracts\fi
  \if@ACM@printccs
  \ifx\@concepts\@empty\else\bgroup
      {\@specialsection{CCS Concepts}%
         \noindent\@concepts\par}\egroup
     \fi
   \fi
   \if@ACM@acmcp\else
     \ifx\@keywords\@empty\else\bgroup
        {\@specialsection{\keywordsname}%
           \noindent\@keywords\par}\egroup
     \fi
    \ifx\@translatedkeywords\@empty\else
       \@translatedkeywords
    \fi
  \fi
  \let\metadata@authors=\authors
  \nxandlist{, }{, }{, }\metadata@authors
  \def\@ACM@checkaffil{}%
  \hypersetup{%
    pdfauthor={\metadata@authors},
    pdftitle={\@title},
    pdfsubject={\@concepts},
    pdfkeywords={\@keywords},
    pdfcreator={LaTeX with acmart
      \csname ver@acmart.cls\endcsname\space
      and hyperref
      \csname ver@hyperref.sty\endcsname}}%
  \andify\authors
  \andify\shortauthors
  \global\let\authors=\authors
  \global\let\shortauthors=\shortauthors
  \if@ACM@printacmref
     \@mkbibcitation
  \fi
  \global\@topnum\z@ % this prevents floats from falling
                     % at the top of page 1
  \global\@botnum\z@ % we do not want them to be on the bottom either
  \@printendtopmatter
  \@afterindentfalse
  \@afterheading
  \if@ACM@acmcp
    \set@ACM@acmcpbox
    \AtEndDocument{\end@ACM@color@frame}%
    \@ACM@color@frame
  \fi
}
\newbox\@ACM@acmcpbox
\def\set@ACM@acmcpbox{%
  \bgroup
  \hsize=5pc
  \global\setbox\@ACM@acmcpbox=\vbox{%
    \setlength{\parindent}{\z@}%
    {\includegraphics[width=\hsize]{acm-jdslogo}\par}%
    \scriptsize
    \ifnum\getrefnumber{TotPages}>1\else
      \zrefused{@ACM@acmcpbox@y}%
      \zrefused{@ACM@acmcpframe@y}%
      \@tempdima=\dimexpr\zposy{@ACM@acmcpbox@y}sp -
      \zposy{@ACM@acmcpframe@y}sp+0.3\FrameSep+
      \@ACM@acmcp@delta\relax
      \ifdim\@tempdima>0pt\relax
         \vspace*{\@tempdima}%
         \protected@write\@auxout{}%
         {\string\global\@ACM@acmcp@delta=\the\@tempdima\relax}%
      \fi
    \fi
    \ifx\@acmCodeDataLink\@empty\else\bigskip
    Code and data links:\\ \@acmCodeDataLink\par\bigskip
    \fi
    \ifx\@keywords\@empty\else\bigskip
      Keywords: \@keywords\par
    \fi
    \ifx\@acmContributions\@empty\else\bigskip
      \@acmContributions\par
    \fi
    \ifx\@empty\@authorsaddresses\else\bigskip\@setauthorsaddresses\fi
    \zsaveposy{@ACM@acmcpbox@y}%
  }
\egroup}
\def\@specialsection#1{%
  \let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig
  \ifcase\ACM@format@nr
  \relax % manuscript
    \par\medskip\small\noindent#1: %
  \or % acmsmall
    \par\medskip\small\noindent#1: %
  \or % acmlarge
    \par\medskip\small\noindent#1: %
  \or % acmtog
    \par\medskip\small\noindent#1: %
  \or % sigconf
    \section*{#1}%
  \or % siggraph
    \section*{#1}%
  \or % sigplan
     \noindentparagraph*{#1:~}%
  \or % sigchi
    \section*{#1}%
  \or % sigchi-a
    \section*{#1}%
  \or % acmengage
    \section*{#1}%
  \or % acmcp
    \section*{#1}%
    \fi
  \let\@vspace\@vspace@acm
  \let\@vspacer\@vspacer@acm
}
\def\@printtopmatter{%
  \ifx\@startPage\@empty
     \gdef\@startPage{1}%
  \else
     \setcounter{page}{\@startPage}%
  \fi
  \@tempdima=\ht\mktitle@bx
  \advance\@tempdima by \dp\mktitle@bx
  \ifdim\@tempdima>0.9\textheight
    \loop
      \setbox\@tempboxa=\vsplit \mktitle@bx to 0.9\textheight
      \thispagestyle{firstpagestyle}%
      \noindent\unvbox\@tempboxa
      \clearpage
      \@tempdima=\ht\mktitle@bx
      \advance\@tempdima by \dp\mktitle@bx
    \ifdim\@tempdima>0.9\textheight\repeat
  \fi
  \thispagestyle{firstpagestyle}%
  \noindent
  \ifcase\ACM@format@nr
  \relax % manuscript
    \box\mktitle@bx\par
  \or % acmsmall
    \box\mktitle@bx\par
  \or % acmlarge
    \box\mktitle@bx\par
  \or % acmtog
    \twocolumn[\box\mktitle@bx]%
  \or % sigconf
    \twocolumn[\box\mktitle@bx]%
  \or % siggraph
    \twocolumn[\box\mktitle@bx]%
  \or % sigplan
    \twocolumn[\box\mktitle@bx]%
  \or % sigchi
    \twocolumn[\box\mktitle@bx]%
  \or % sigchi-a
    \par\box\mktitle@bx\par\bigskip
  \or % acmengage
    \twocolumn[\box\mktitle@bx]%
  \or % acmcp
     \box\mktitle@bx\par
  \fi
}
\def\@mktitle{%
  \ifcase\ACM@format@nr
  \relax % manuscript
    \@mktitle@i
  \or % acmsmall
    \@mktitle@i
  \or % acmlarge
    \@mktitle@i
  \or % acmtog
    \@mktitle@i
  \or % sigconf
    \@mktitle@iii
  \or % siggraph
    \@mktitle@iii
  \or % sigplan
    \@mktitle@iii
  \or % sigchi
    \@mktitle@iii
  \or % sigchi-a
    \@mktitle@iv
  \or % acmengage
    \@mktitle@iii
  \or % acmcp
    \@mktitle@i
  \fi
}
\def\@titlefont{%
  \ifcase\ACM@format@nr
  \relax % manuscript
    \LARGE\sffamily\bfseries
  \or % acmsmall
    \LARGE\sffamily\bfseries
  \or % acmlarge
    \LARGE\sffamily\bfseries
  \or % acmtog
    \Huge\sffamily
  \or % sigconf
    \Huge\sffamily\bfseries
  \or % siggraph
    \Huge\sffamily\bfseries
  \or % sigplan
    \Huge\bfseries
  \or % sigchi
    \Huge\sffamily\bfseries
  \or % sigchi-a
     \Huge\bfseries
  \or % acmengage
    \Huge\sffamily\bfseries
  \or % acmcp
    \LARGE\sffamily\bfseries
  \fi}
\def\@subtitlefont{\normalsize
  \ifcase\ACM@format@nr
  \relax % manuscript
    \mdseries
  \or % acmsmall
    \mdseries
  \or % acmlarge
    \mdseries
  \or % acmtog
     \LARGE
  \or % sigconf
     \LARGE\mdseries
  \or % siggraph
     \LARGE\mdseries
  \or % sigplan
     \LARGE\mdseries
  \or % sigchi
     \LARGE\mdseries
  \or % sigchi-a
     \mdseries
  \or % acmengage
     \LARGE\mdseries
  \or % acmcp
    \mdseries
  \fi}
\def\@mktitle@i{\hsize=\textwidth
  \if@ACM@acmcp
    \advance\hsize by -6pc%
  \fi
  \@ACM@title@width=\hsize
  \setbox\mktitle@bx=\vbox{\noindent\@titlefont
    \parbox[t]{\@ACM@title@width}{\raggedright
      \@titlefont\noindent
      \@title\@translatedtitle%
  \ifx\@subtitle\@empty\else
    \par\noindent{\@subtitlefont\@subtitle\@translatedsubtitle}%
  \fi}%
  \par\bigskip}}%
\def\@mktitle@iii{\hsize=\textwidth
    \setbox\mktitle@bx=\vbox{\@titlefont\centering
      \@ACM@title@width=\hsize
      \parbox[t]{\@ACM@title@width}{\centering\@titlefont
        \@title\@translatedtitle%
        \ifx\@subtitle\@empty\else
          \par\noindent{\@subtitlefont\@subtitle\@translatedsubtitle}
        \fi
      }%
      \par\bigskip}}%
\def\@mktitle@iv{\hsize=\textwidth
    \setbox\mktitle@bx=\vbox{\raggedright\leftskip5pc\@titlefont
      \noindent\leavevmode\leaders\hrule height 2pt\hfill\kern0pt\par
      \noindent\@title\@translatedtitle%
     \ifx\@subtitle\@empty\else
       \par\noindent\@subtitlefont\@subtitle\@translatedsubtitle%
     \fi
     \par\bigskip}}%
\newbox\@ACM@commabox
\def\@ACM@addtoaddress#1{%
  \ifvmode\else
    \if@ACM@affiliation@obeypunctuation\else
    \setbox\@ACM@commabox=\hbox{, }%
    \unskip\cleaders\copy\@ACM@commabox\hskip\wd\@ACM@commabox
  \fi\fi
  #1}
\def\streetaddress#1{\unskip\ignorespaces}
\def\postcode#1{\unskip\ignorespaces}
\if@ACM@journal
  \def\position#1{\unskip\ignorespaces}
  \def\institution#1{\global\@ACM@instpresenttrue
    \unskip~#1\ignorespaces}
  \def\city#1{\global\@ACM@citypresenttrue\unskip\ignorespaces}
  \def\state#1{\unskip\ignorespaces}
  \newcommand\department[2][0]{\unskip\ignorespaces}
  \def\country#1{\StrDel{#1}{ }[\@tempa]%
    \ifx\@tempa\@empty\else
    \global\@ACM@countrypresenttrue\fi
    \if@ACM@affiliation@obeypunctuation\else, \fi#1\ignorespaces}
\else
  \def\position#1{\if@ACM@affiliation@obeypunctuation#1\else#1\par\fi}%
  \def\institution#1{\global\@ACM@instpresenttrue
    \if@ACM@affiliation@obeypunctuation#1\else#1\par\fi}%
  \newcommand\department[2][0]{\if@ACM@affiliation@obeypunctuation
    #2\else#2\par\fi}%
  \def\city#1{\global\@ACM@citypresenttrue\@ACM@addtoaddress{#1}}%
  \let\state\@ACM@addtoaddress
  \def\country#1{\global\@ACM@countrypresenttrue\@ACM@addtoaddress{#1}}%
\fi
\def\@mkauthors{\begingroup
  \hsize=\textwidth
  \ifcase\ACM@format@nr
  \relax % manuscript
    \@mkauthors@i
  \or % acmsmall
    \@mkauthors@i
  \or % acmlarge
    \@mkauthors@i
  \or % acmtog
    \@mkauthors@i
  \or % sigconf
    \@mkauthors@iii
  \or % siggraph
    \@mkauthors@iii
  \or % sigplan
    \@mkauthors@iii
  \or % sigchi
    \@mkauthors@iii
  \or % sigchi-a
    \@mkauthors@iv
  \or % acmengage
    \@mkauthors@iii
  \or % acmcp
    \@mkauthors@i
  \fi
  \endgroup
}
\def\@authorfont{\Large\sffamily}
\def\@affiliationfont{\normalsize\normalfont}
\ifcase\ACM@format@nr
\relax % manuscript
\or % acmsmall
  \def\@authorfont{\large\sffamily}
  \def\@affiliationfont{\small\normalfont}
\or % acmlarge
\or % acmtog
  \def\@authorfont{\LARGE\sffamily}
  \def\@affiliationfont{\large}
\or % sigconf
  \def\@authorfont{\LARGE}
  \def\@affiliationfont{\large}
\or % siggraph
  \def\@authorfont{\normalsize\normalfont}
  \def\@affiliationfont{\normalsize\normalfont}
\or % sigplan
  \def\@authorfont{\Large\normalfont}
  \def\@affiliationfont{\normalsize\normalfont}
\or % sigchi
  \def\@authorfont{\bfseries}
  \def\@affiliationfont{\mdseries}
\or % sigchi-a
  \def\@authorfont{\bfseries}
  \def\@affiliationfont{\mdseries}
\or % acmengage
  \def\@authorfont{\LARGE}
  \def\@affiliationfont{\large}
\or % acmcp
  \def\@authorfont{\large\sffamily}
  \def\@affiliationfont{\small\normalfont}
\fi
\def\@typeset@author@line{%
  \andify\@currentauthors\par\noindent
  \@currentauthors\def\@currentauthors{}%
  \ifx\@currentaffiliations\@empty\else
    \andify\@currentaffiliations
      \unskip, {\@currentaffiliations}\par
  \fi
  \def\@currentaffiliations{}}
\newif\if@ACM@instpresent
\@ACM@instpresenttrue
\newif\if@ACM@citypresent
\@ACM@citypresenttrue
\newif\if@ACM@countrypresent
\@ACM@countrypresenttrue
\def\@ACM@resetaffil{%
  \global\@ACM@instpresentfalse
  \global\@ACM@citypresentfalse
  \global\@ACM@countrypresentfalse
}
\def\@ACM@checkaffil{%
  \if@ACM@instpresent\else
  \ClassWarningNoLine{\@classname}{No institution present for an affiliation}%
  \fi
  \if@ACM@citypresent\else
  \ClassWarningNoLine{\@classname}{No city present for an affiliation}%
  \fi
  \if@ACM@countrypresent\else
  \ClassError{\@classname}{No country present for an affiliation}{ACM
    requires each author to indicate their country using country macro.}%
  \fi
}
\def\@mkauthors@i{%
  \def\@currentauthors{}%
  \def\@currentaffiliations{}%
  \global\let\and\@typeset@author@line
  \def\@author##1{%
    \ifx\@currentauthors\@empty
      \gdef\@currentauthors{\@authorfont\MakeTextUppercase{##1}}%
    \else
       \g@addto@macro{\@currentauthors}{\and\MakeTextUppercase{##1}}%
    \fi
    \gdef\and{}}%
  \def\email##1##2{}%
  \def\affiliation##1##2{%
    \def\@tempa{##2}\ifx\@tempa\@empty\else
       \ifx\@currentaffiliations\@empty
          \gdef\@currentaffiliations{%
            \setkeys{@ACM@affiliation@}{obeypunctuation=false}%
            \setkeys{@ACM@affiliation@}{##1}%
            \@ACM@resetaffil
            \@affiliationfont##2\@ACM@checkaffil}%
       \else
         \g@addto@macro{\@currentaffiliations}{\and
           \setkeys{@ACM@affiliation@}{obeypunctuation=false}%
           \setkeys{@ACM@affiliation@}{##1}\@ACM@resetaffil
           ##2\@ACM@checkaffil}%
      \fi
    \fi
     \global\let\and\@typeset@author@line}%
  \if@ACM@acmcp
    \advance\hsize by -6pc%
  \fi
  \global\setbox\mktitle@bx=\vbox{\noindent\unvbox\mktitle@bx\par\medskip
    \noindent\addresses\@typeset@author@line
   \par\medskip}%
}
\newbox\author@bx
\newdimen\author@bx@wd
\newskip\author@bx@sep
\author@bx@sep=1pc\relax
\def\@typeset@author@bx{\bgroup\hsize=\author@bx@wd
  \def\and{\par}\normalbaselines
  \global\setbox\author@bx=\vtop{\if@ACM@sigchiamode\else\centering\fi
    \@authorfont\@currentauthors\par\@affiliationfont
    \@currentaffiliation}\egroup
  \box\author@bx\hspace{\author@bx@sep}%
  \gdef\@currentauthors{}%
  \gdef\@currentaffiliation{}}
\def\@mkauthors@iii{%
  \author@bx@wd=\textwidth\relax
  \advance\author@bx@wd by -\author@bx@sep\relax
  \ifnum\@ACM@authorsperrow>0\relax
    \divide\author@bx@wd by \@ACM@authorsperrow\relax
  \else
    \ifcase\num@authorgroups
    \relax % 0?
    \or  % 1=one author per row
    \or  % 2=two authors per row
       \divide\author@bx@wd by \num@authorgroups\relax
    \or  % 3=three authors per row
       \divide\author@bx@wd by \num@authorgroups\relax
    \or  % 4=two authors per row (!)
       \divide\author@bx@wd by 2\relax
    \else % three authors per row
       \divide\author@bx@wd by 3\relax
    \fi
  \fi
  \advance\author@bx@wd by -\author@bx@sep\relax
  \gdef\@currentauthors{}%
  \gdef\@currentaffiliation{}%
  \def\@author##1{\ifx\@currentauthors\@empty
    \gdef\@currentauthors{\par##1}%
  \else
    \g@addto@macro\@currentauthors{\par##1}%
  \fi
  \gdef\and{}}%
  \def\email##1##2{\ifx\@currentaffiliation\@empty
    \gdef\@currentaffiliation{\bgroup
      \mathchardef\UrlBreakPenalty=10000\nolinkurl{##2}\egroup}%
  \else
    \g@addto@macro\@currentaffiliation{\par\bgroup
      \mathchardef\UrlBreakPenalty=10000\nolinkurl{##2}\egroup}%
  \fi}%
  \def\affiliation##1##2{\ifx\@currentaffiliation\@empty
    \gdef\@currentaffiliation{%
      \setkeys{@ACM@affiliation@}{obeypunctuation=false}%
      \setkeys{@ACM@affiliation@}{##1}\@ACM@resetaffil
      ##2\@ACM@checkaffil}%
  \else
    \g@addto@macro\@currentaffiliation{\par
      \setkeys{@ACM@affiliation@}{obeypunctuation=false}%
      \setkeys{@ACM@affiliation@}{##1}\@ACM@resetaffil
      ##2\@ACM@checkaffil}%
  \fi
  \global\let\and\@typeset@author@bx
}%
  \hsize=\textwidth
  \global\setbox\mktitle@bx=\vbox{\noindent
    \unvbox\mktitle@bx\par\medskip\leavevmode
    \lineskip=1pc\relax\centering\hspace*{-1em}%
    \addresses\let\and\@typeset@author@bx\and\par\bigskip}}
\def\@mkauthors@iv{%
  \author@bx@wd=\columnwidth\relax
  \advance\author@bx@wd by -\author@bx@sep\relax
  \ifnum\@ACM@authorsperrow>0\relax
    \divide\author@bx@wd by \@ACM@authorsperrow\relax
  \else
    \ifcase\num@authorgroups
    \relax % 0?
    \or  % 1=one author per row
    \else  % 2=two authors per row
       \divide\author@bx@wd by 2\relax
    \fi
  \fi
  \advance\author@bx@wd by -\author@bx@sep\relax
  \gdef\@currentauthors{}%
  \gdef\@currentaffiliation{}%
  \def\@author##1{\ifx\@currentauthors\@empty
    \gdef\@currentauthors{\par##1}%
  \else
    \g@addto@macro\@currentauthors{\par##1}%
  \fi
  \gdef\and{}}%
  \def\email##1##2{\ifx\@currentaffiliation\@empty
    \gdef\@currentaffiliation{\nolinkurl{##2}}%
  \else
    \g@addto@macro\@currentaffiliation{\par\nolinkurl{##2}}%
  \fi}%
  \def\affiliation##1##2{\ifx\@currentaffiliation\@empty
    \gdef\@currentaffiliation{%
      \setkeys{@ACM@affiliation@}{obeypunctuation=false}%
      \setkeys{@ACM@affiliation@}{##1}\@ACM@resetaffil
      ##2\@ACM@checkaffil}%
  \else
    \g@addto@macro\@currentaffiliation{\par
      \setkeys{@ACM@affiliation@}{obeypunctuation=false}%
      \setkeys{@ACM@affiliation@}{##1}\@ACM@resetaffil
      ##2\@ACM@checkaffil}%
  \fi
  \global\let\and\@typeset@author@bx}%
    \bgroup\hsize=\columnwidth
    \par\raggedright\leftskip=\z@
    \lineskip=1pc\noindent
    \addresses\let\and\@typeset@author@bx\and\par\bigskip\egroup}
\def\@mkauthorsaddresses{%
  \ifnum\num@authors>1\relax
  Authors' \else Author's \fi
  \ifnum\num@authorgroups>1\relax
  addresses: \else address: \fi
  \bgroup
  \def\streetaddress##1{\unskip, ##1}%
  \def\postcode##1{\unskip, ##1}%
  \def\position##1{\unskip\ignorespaces}%
  \gdef\@ACM@institution@separator{, }%
  \def\institution##1{\unskip\@ACM@institution@separator ##1\gdef\@ACM@institution@separator{ and }}%
  \def\city##1{\unskip, ##1}%
  \def\state##1{\unskip, ##1}%
  \renewcommand\department[2][0]{\unskip\@addpunct, ##2}%
  \def\country##1{\unskip, ##1}%
  \def\and{\unskip; \gdef\@ACM@institution@separator{, }}%
  \def\@author##1{##1}%
  \def\email##1##2{\unskip, \nolinkurl{##2}}%
  \addresses
  \egroup}
\AtEndDocument{\if@ACM@nonacm\else\if@ACM@journal
  \ifx\@authorsaddresses\@empty
  \ClassWarningNoLine{\@classname}{Authors'
    addresses are mandatory for ACM journals}%
  \fi\fi\fi}
\def\@setaddresses{}
\def\@authornotemark{\g@addto@macro\@currentauthors{\footnotemark\relax}}
\def\@@authornotemark#1{\g@addto@macro\@currentauthors{\footnotemark[#1]}}
\def\@mkteasers{%
  \ifx\@teaserfigures\@empty\else
    \def\@teaser##1{\par\bigskip\bgroup
      \captionsetup{type=figure}##1\egroup\par}
    \global\setbox\mktitle@bx=\vbox{\noindent\unvbox\mktitle@bx\par
      \noindent\@Description@presentfalse
      \@teaserfigures\par\if@Description@present\else
         \global\@undescribed@imagestrue
         \ClassWarning{\@classname}{A possible image without
           description}\fi
    \medskip}%
  \fi}
\def\@mkabstract{\bgroup
  \ifx\@abstract\@lempty\else
  {\phantomsection\addcontentsline{toc}{section}{\abstractname}%
    \if@ACM@journal
       \everypar{\setbox\z@\lastbox\everypar{}}\small
    \else
      \section*{\abstractname}%
    \fi
   \ignorespaces\@abstract\par}%
  \fi\egroup}
\def\@mktranslatedabstract#1{\selectlanguage{#1}%
    \if@ACM@journal
       \everypar{\setbox\z@\lastbox\everypar{}}\small
    \else
       \section*{\abstractname}%
    \fi
   \ignorespaces}
\def\@mkbibcitation{\bgroup
  \let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig
  \def\@pages@word{\ifnum\getrefnumber{TotPages}=1\relax page\else pages\fi}%
  \def\footnotemark{}%
  \def\\{\unskip{} \ignorespaces}%
  \def\footnote{\ClassError{\@classname}{Please do not use footnotes
      inside a \string\title{} or \string\author{} command! Use
      \string\titlenote{} or \string\authornote{} instead!}}%
  \def\@article@string{\ifx\@acmArticle\@empty{\ }\else,
    Article~\@acmArticle\ \fi}%
  \par\medskip\small\noindent{\bfseries ACM Reference Format:}\par\nobreak
  \noindent\bgroup
    \def\\{\unskip{}, \ignorespaces}\authors\egroup. \@acmYear. \@title
  \ifx\@subtitle\@empty. \else: \@subtitle. \fi
  \if@ACM@nonacm\else
    % The 'nonacm' option disables 'printacmref' by default,
    % and the present \@mkbibcitation definition is never used
    % in this case. The conditional remains useful if the user
    % explicitly sets \settopmatter{printacmref=true}.
    \if@ACM@journal@bibstrip
       \textit{\@journalNameShort}
       \@acmVolume, \@acmNumber \@article@string (\@acmPubDate),
       \ref{TotPages}~\@pages@word.
    \else
       In \textit{\@acmBooktitle}%
       \ifx\@acmEditors\@empty\textit{.}\else
         \andify\@acmEditors\textit{, }\@acmEditors~\@editorsAbbrev.%
       \fi\
       ACM, New York, NY, USA%
         \@article@string\unskip, \ref{TotPages}~\@pages@word.
    \fi
  \fi
  \ifx\@acmDOI\@empty\else\@formatdoi{\@acmDOI}\fi
\par\egroup}
\def\@printendtopmatter{%
  \let\@vspace\@vspace@orig
  \let\@vspacer\@vspacer@orig
  \par\bigskip
  \let\@vspace\@vspace@acm
  \let\@vspacer\@vspacer@acm
  }
\def\@setthanks{\long\def\thanks##1{\par##1\@addpunct.}\thankses}
\def\@setauthorsaddresses{\@authorsaddresses\unskip\@addpunct.}
\def\@typesetengagemetadata{%
  \def\@setengagemetadata##1##2{\par\noindent\textbf{##1} ##2\par}%
  \@acmengagemetadata}
\RequirePackage{fancyhdr}
\let\ACM@ps@plain\ps@plain
\let\ACM@ps@myheadings\ps@myheadings
\let\ACM@ps@headings\ps@headings
\def\ACM@restore@pagestyle{%
  \let\ps@plain\ACM@ps@plain
  \let\ps@myheadings\ACM@ps@myheadings
  \let\ps@headings\ACM@ps@headings}
\AtBeginDocument{\ACM@restore@pagestyle}
\if@ACM@review
  \newsavebox{\ACM@linecount@bx}
  \newlength\ACM@linecount@bxht
  \newcount\ACM@linecount
  \ACM@linecount\@ne\relax
  \def\ACM@mk@linecount{%
    \savebox{\ACM@linecount@bx}[4em][t]{\parbox[t]{4em}{\normalfont
        \normalsize
        \setlength{\ACM@linecount@bxht}{0pt}%
        \loop{\color{red}\scriptsize\the\ACM@linecount}\\
        \global\advance\ACM@linecount by \@ne
        \addtolength{\ACM@linecount@bxht}{\baselineskip}%
        \ifdim\ACM@linecount@bxht<\textheight\repeat
        {\color{red}\scriptsize\the\ACM@linecount}\hfill
        \global\advance\ACM@linecount by \@ne}}}
\fi
\def\ACM@linecountL{%
  \if@ACM@review
  \ACM@mk@linecount
  \begin{picture}(0,0)%
    \put(-26,-22){\usebox{\ACM@linecount@bx}}%
  \end{picture}%
  \fi}
\def\ACM@linecountR{%
  \if@ACM@review
    \ifcase\ACM@format@nr
    \relax % manuscript
         \relax
       \or % acmsmall
         \relax
       \or % acmlarge
         \relax
       \or % acmtog
          \ACM@mk@linecount
       \or % sigconf
          \ACM@mk@linecount
       \or % siggraph
          \ACM@mk@linecount
       \or % sigplan
          \ACM@mk@linecount
       \or % sigchi
          \ACM@mk@linecount
       \or % sigchi-a
          \ACM@mk@linecount
       \or % acmengage
          \ACM@mk@linecount
       \or % acmcp
         \relax
    \fi
    \begin{picture}(0,0)%
      \put(20,-22){\usebox{\ACM@linecount@bx}}%
     \end{picture}%
  \fi}
\if@ACM@timestamp
  % Subtracting 30 from \time gives us the effect of rounding down despite
  % \numexpr rounding to nearest
  \newcounter{ACM@time@hours}
  \setcounter{ACM@time@hours}{\numexpr (\time - 30) / 60 \relax}
  \newcounter{ACM@time@minutes}
  \setcounter{ACM@time@minutes}{\numexpr \time - \theACM@time@hours * 60 \relax}
  \newcommand\ACM@timestamp{%
    \footnotesize%
    \ifx\@acmSubmissionID\@empty\relax\else
    Submission ID: \@acmSubmissionID.{ }%
    \fi
    \the\year-\two@digits{\the\month}-\two@digits{\the\day}{ }%
    \two@digits{\theACM@time@hours}:\two@digits{\theACM@time@minutes}{. }%
    Page \thepage\ of \@startPage--\pageref*{TotPages}.%
  }
\fi
\def\@shortauthors{%
  \if@ACM@anonymous
    Anon.
    \ifx\@acmSubmissionID\@empty\else Submission Id: \@acmSubmissionID\fi
  \else\shortauthors\fi}
\def\@headfootfont{\sffamily\footnotesize}
\AtBeginDocument{%
\fancypagestyle{standardpagestyle}{%
  \fancyhf{}%
  \renewcommand{\headrulewidth}{\z@}%
  \renewcommand{\footrulewidth}{\z@}%
  \def\@acmArticlePage{%
    \ifx\@acmArticle\empty%
      \if@ACM@printfolios\thepage\fi%
    \else%
      \@acmArticle\if@ACM@printfolios:\thepage\fi%
    \fi%
  }%
  \if@ACM@journal@bibstrip
    \ifcase\ACM@format@nr
    \relax % manuscript
      \fancyhead[LE]{\ACM@linecountL\if@ACM@printfolios\thepage\fi}%
      \fancyhead[RO]{\if@ACM@printfolios\thepage\fi}%
      \fancyhead[RE]{\@shortauthors}%
      \fancyhead[LO]{\ACM@linecountL\shorttitle}%
      \if@ACM@nonacm\else%
        \fancyfoot[RO,LE]{\footnotesize Manuscript submitted to ACM}
      \fi%
    \or % acmsmall
      \fancyhead[LE]{\ACM@linecountL\@headfootfont\@acmArticlePage}%
      \fancyhead[RO]{\@headfootfont\@acmArticlePage}%
      \fancyhead[RE]{\@headfootfont\@shortauthors}%
      \fancyhead[LO]{\ACM@linecountL\@headfootfont\shorttitle}%
      \if@ACM@nonacm\else%
        \fancyfoot[RO,LE]{\footnotesize \@journalNameShort, Vol. \@acmVolume, No.
        \@acmNumber, Article \@acmArticle.  Publication date: \@acmPubDate.}%
      \fi
    \or % acmlarge
      \fancyhead[LE]{\ACM@linecountL\@headfootfont
      \@acmArticlePage\quad\textbullet\quad\@shortauthors}%
      \fancyhead[LO]{\ACM@linecountL}%
      \fancyhead[RO]{\@headfootfont
        \shorttitle\quad\textbullet\quad\@acmArticlePage}%
      \if@ACM@nonacm\else%
        \fancyfoot[RO,LE]{\footnotesize \@journalNameShort, Vol. \@acmVolume, No.
        \@acmNumber, Article \@acmArticle.  Publication date: \@acmPubDate.}%
      \fi
    \or % acmtog
      \fancyhead[LE]{\ACM@linecountL\@headfootfont
        \@acmArticlePage\quad\textbullet\quad\@shortauthors}%
      \fancyhead[LO]{\ACM@linecountL}%
      \fancyhead[RE]{\ACM@linecountR}%
      \fancyhead[RO]{\@headfootfont
        \shorttitle\quad\textbullet\quad\@acmArticlePage\ACM@linecountR}%
      \if@ACM@nonacm\else%
        \fancyfoot[RO,LE]{\footnotesize \@journalNameShort, Vol. \@acmVolume, No.
        \@acmNumber, Article \@acmArticle.  Publication date: \@acmPubDate.}%
      \fi
    \else % Proceedings
      \fancyfoot[C]{\if@ACM@printfolios\footnotesize\thepage\fi}%
      \fancyhead[LO]{\ACM@linecountL\@headfootfont\shorttitle}%
      \fancyhead[RE]{\@headfootfont\@shortauthors\ACM@linecountR}%
      \if@ACM@nonacm
        \fancyhead[LE]{\ACM@linecountL}%
        \fancyhead[RO]{\ACM@linecountR}%
      \else%
        \if@ACM@engage
          \fancyhead[LE]{\ACM@linecountL\@headfootfont\footnotesize
            EngageCSEdu. \ifx\@acmDOI\@empty\else\@formatdoi{\@acmDOI}\fi}%
          \fancyhead[RO]{\@headfootfont
            EngageCSEdu. \ifx\@acmDOI\@empty\else\@formatdoi{\@acmDOI}\fi
            \ACM@linecountR}%
        \else
          \fancyhead[LE]{\ACM@linecountL\@headfootfont\footnotesize
            \acmConference@shortname,
            \acmConference@date, \acmConference@venue}%
          \fancyhead[RO]{\@headfootfont
            \acmConference@shortname,
            \acmConference@date, \acmConference@venue\ACM@linecountR}%
         \fi
      \fi
    \fi
  \else % Proceedings
    \fancyfoot[C]{\if@ACM@printfolios\footnotesize\thepage\fi}%
    \fancyhead[LO]{\ACM@linecountL\@headfootfont\shorttitle}%
    \fancyhead[RE]{\@headfootfont\@shortauthors\ACM@linecountR}%
    \if@ACM@nonacm
      \fancyhead[LE]{\ACM@linecountL}%
      \fancyhead[RO]{\ACM@linecountR}%
    \else%
      \if@ACM@engage
        \fancyhead[LE]{\ACM@linecountL\@headfootfont
          EngageCSEdu. \ifx\@acmDOI\@empty\else\@formatdoi{\@acmDOI}\fi}%
        \fancyhead[RO]{\@headfootfont
          EngageCSEdu. \ifx\@acmDOI\@empty\else\@formatdoi{\@acmDOI}\fi
          \ACM@linecountR}%
      \else
        \fancyhead[LE]{\ACM@linecountL\@headfootfont
          \acmConference@shortname,
          \acmConference@date, \acmConference@venue}%
        \fancyhead[RO]{\@headfootfont
          \acmConference@shortname,
          \acmConference@date, \acmConference@venue\ACM@linecountR}%
       \fi
    \fi
  \fi
  \if@ACM@sigchiamode
     \fancyheadoffset[L]{\dimexpr(\marginparsep+\marginparwidth)}%
  \fi
  \if@ACM@timestamp
     \fancyfoot[LO,RE]{\ACM@timestamp}
  \fi
  \if@ACM@acmcp
  \renewcommand{\footrulewidth}{0.1\p@}%
  \fancyheadoffset[L]{46pt}%
  \fancyhead[L]{\makebox[\z@][l]{%
      \raisebox{-\dimexpr(0.2\textheight*(\ACM@ArticleType@nr-2))}{%
      \rotatebox{90}{\colorbox{@ACM@Article@color}{\color{white}%
          \strut\ACM@ArticleType~Article}}}}%
    \ACM@linecountL}%
  \fancyhead[R]{\makebox[\z@][r]{\box\@ACM@acmcpbox}}%
  \fancyfoot[L,C]{}%
  \fancyfoot[R]{\footnotesize
    \@journalName, Volume~\@acmVolume, Issue~\@acmNumber,
    \ifx\@acmArticle\@empty\else Article~\@acmArticle\fi\space
    (\@acmPubDate)\ifx\@acmDOI\@empty\else\\\@formatdoi{\@acmDOI}\fi}
  \fi
}%
\pagestyle{standardpagestyle}
}
\AtBeginDocument{%
\fancypagestyle{firstpagestyle}{%
  \fancyhf{}%
  \renewcommand{\headrulewidth}{\z@}%
  \renewcommand{\footrulewidth}{\z@}%
  \if@ACM@journal@bibstrip
    \ifcase\ACM@format@nr
    \relax % manuscript
      \fancyhead[L]{\ACM@linecountL\@acmBadgeL}%
      \fancyhead[R]{\@acmBadgeR}%
      \fancyfoot[RO,LE]{\if@ACM@printfolios\small\thepage\fi}%
      \if@ACM@nonacm\else%
        \fancyfoot[RE,LO]{\footnotesize Manuscript submitted to ACM}%
      \fi%
    \or % acmsmall
      \if@ACM@nonacm\else%
        \fancyfoot[RO,LE]{\footnotesize \@journalNameShort, Vol. \@acmVolume, No.
        \@acmNumber, Article \@acmArticle.  Publication date:
        \@acmPubDate.}%
      \fi%
      \fancyhead[LE]{\ACM@linecountL\@acmBadgeL}%
      \fancyhead[LO]{\ACM@linecountL\@acmBadgeL}%
      \fancyhead[RO]{\@acmBadgeR}%
      \fancyhead[RE]{\@acmBadgeR}%
    \or % acmlarge
      \if@ACM@nonacm\else%
        \fancyfoot[RO,LE]{\footnotesize \@journalNameShort, Vol. \@acmVolume, No.
        \@acmNumber, Article \@acmArticle.  Publication date:
        \@acmPubDate.}%
      \fi%
      \fancyhead[RO]{\@acmBadgeR}%
      \fancyhead[RE]{\@acmBadgeR}%
      \fancyhead[LE]{\ACM@linecountL\@acmBadgeL}%
      \fancyhead[LO]{\ACM@linecountL\@acmBadgeL}%
    \or % acmtog
      \if@ACM@nonacm\else%
        \fancyfoot[RO,LE]{\footnotesize \@journalNameShort, Vol. \@acmVolume, No.
        \@acmNumber, Article \@acmArticle.  Publication date:
        \@acmPubDate.}%
      \fi%
      \fancyhead[L]{\ACM@linecountL\@acmBadgeL}%
      \fancyhead[R]{\@acmBadgeR\ACM@linecountR}%
    \else % Conference proceedings
      \fancyhead[L]{\ACM@linecountL\@acmBadgeL}%
      \fancyhead[R]{\@acmBadgeR\ACM@linecountR}%
      \fancyfoot[C]{\if@ACM@printfolios\footnotesize\thepage\fi}%
    \fi
  \else
    \fancyhead[L]{\ACM@linecountL\@acmBadgeL}%
    \fancyhead[R]{\@acmBadgeR\ACM@linecountR}%
    \fancyfoot[C]{\if@ACM@printfolios\footnotesize\thepage\fi}%
  \fi
  \if@ACM@timestamp
    \ifnum\ACM@format@nr=0\relax % Manuscript
    \fancyfoot[LO,RE]{\ACM@timestamp\quad
      \if@ACM@nonacm\else
        \footnotesize Manuscript submitted to ACM
      \fi}
    \else
    \fancyfoot[LO,RE]{\ACM@timestamp}
    \fi
  \fi
  \if@ACM@acmcp
  \renewcommand{\footrulewidth}{0.1\p@}%
  \fancyheadoffset[L]{46pt}%
  \fancyhead[L]{\makebox[\z@][l]{%
      \raisebox{-\dimexpr(0.2\textheight*(\ACM@ArticleType@nr-2))}{%
      \rotatebox{90}{\colorbox{@ACM@Article@color}{\color{white}%
          \strut\ACM@ArticleType~Article}}}}%
    \ACM@linecountL\@acmBadgeL}%
  \fancyhead[R]{\@acmBadgeR\makebox[\z@][r]{\box\@ACM@acmcpbox}}%
  \fancyfoot[L,C]{}%
  \fancyfoot[R]{\footnotesize
    \@journalName, Volume~\@acmVolume, Issue~\@acmNumber,
    \ifx\@acmArticle\@empty\else Article~\@acmArticle\fi\space
    (\@acmPubDate)\ifx\@acmDOI\@empty\else\\\@formatdoi{\@acmDOI}\fi}
  \fi
}}
\def\ACM@NRadjust#1{%
 \begingroup
  \expandafter\ifx\csname Sectionformat\endcsname\relax
  % do nothing when  \Sectionformat  is unknown
   \def\next{\endgroup #1}%
 \else
  \def\next{\endgroup
   \let\realSectionformat\Sectionformat
   \def\ACM@sect@format@{#1}%
   \let\Sectionformat\ACM@NR@adjustedSectionformat
 %%  next lines added 2018-06-17 to ensure section number is styled
   \let\real@adddotafter\@adddotafter
   \let\@adddotafter\ACM@adddotafter
   #1{}% imposes the styles, but nullifies  \MakeUppercase
   \let\@adddotafter\real@adddotafter
  }%
 \fi \next
}
\def\ACM@NR@adjustedSectionformat#1#2{%
 \realSectionformat{\ACM@sect@format{#1}}{#2}%
 \let\Sectionformat\realSectionformat}
\DeclareRobustCommand{\ACM@sect@format}{\ACM@sect@format@}
\def\ACM@sect@format@null#1{#1}
\let\ACM@sect@format@\ACM@sect@format@null
\AtBeginDocument{%
 \expandafter\ifx\csname LTX@adddotafter\endcsname\relax
  \let\LTX@adddotafter\@adddotafter
 \fi
}
\def\ACM@adddotafter#1{\ifx\relax#1\relax\else\LTX@adddotafter{#1}\fi}
\renewcommand\section{\@startsection{section}{1}{\z@}%
  {-.75\baselineskip \@plus -2\p@ \@minus -.2\p@}%
  {.25\baselineskip}%
  {\ACM@NRadjust\@secfont}}
\renewcommand\subsection{\@startsection{subsection}{2}{\z@}%
  {-.75\baselineskip \@plus -2\p@ \@minus -.2\p@}%
  {.25\baselineskip}%
  {\ACM@NRadjust\@subsecfont}}
\renewcommand\subsubsection{\@startsection{subsubsection}{3}{\z@}%
  {-.5\baselineskip \@plus -2\p@ \@minus -.2\p@}%
  {-3.5\p@}%
  {\ACM@NRadjust{\@subsubsecfont\@adddotafter}}}
\renewcommand\paragraph{\@startsection{paragraph}{4}{\parindent}%
  {-.5\baselineskip \@plus -2\p@ \@minus -.2\p@}%
  {-3.5\p@}%
  {\ACM@NRadjust{\@parfont\@adddotafter}}}
\newcommand\noindentparagraph{\@startsection{paragraph}{4}{\z@}%
  {-.5\baselineskip \@plus -2\p@ \@minus -.2\p@}%
  {-3.5\p@}%
  {\ACM@NRadjust{\@parfont}}}

\renewcommand\part{\@startsection{part}{9}{\z@}%
  {-10\p@ \@plus -4\p@ \@minus -2\p@}%
  {4\p@}%
  {\ACM@NRadjust\@parfont}}
\def\section@raggedright{\@rightskip\@flushglue
  \rightskip\@rightskip
  \leftskip\z@skip
  \parindent\z@}
\def\@secfont{\sffamily\bfseries\section@raggedright\MakeTextUppercase}
\def\@subsecfont{\sffamily\bfseries\section@raggedright}
\def\@subsubsecfont{\sffamily\itshape}
\def\@parfont{\itshape}
\setcounter{secnumdepth}{3}
\ifcase\ACM@format@nr
\relax % manuscript
\or % acmsmall
\or % acmlarge
 \def\@secfont{\sffamily\large\section@raggedright\MakeTextUppercase}
 \def\@subsecfont{\sffamily\large\section@raggedright}
\or % acmtog
 \def\@secfont{\sffamily\large\section@raggedright\MakeTextUppercase}
 \def\@subsecfont{\sffamily\large\section@raggedright}
\or % sigconf
 \def\@secfont{\bfseries\Large\section@raggedright\MakeTextUppercase}
 \def\@subsecfont{\bfseries\Large\section@raggedright}
\or % siggraph
 \def\@secfont{\sffamily\bfseries\Large\section@raggedright\MakeTextUppercase}
 \def\@subsecfont{\sffamily\bfseries\Large\section@raggedright}
\or % sigplan
 \def\@secfont{\bfseries\Large\section@raggedright}
 \def\@subsecfont{\bfseries\section@raggedright}
 \def\@subsubsecfont{\bfseries\section@raggedright}
 \def\@parfont{\bfseries\itshape}
 \def\@subparfont{\itshape}
\or % sigchi
 \setcounter{secnumdepth}{1}
 \def\@secfont{\sffamily\bfseries\section@raggedright\MakeTextUppercase}
 \def\@subsecfont{\sffamily\bfseries\section@raggedright}
\or % sigchi-a
 \setcounter{secnumdepth}{0}
 \def\@secfont{\sffamily\bfseries\section@raggedright\MakeTextUppercase}
 \def\@subsecfont{\sffamily\bfseries\section@raggedright}
\or % acmengage
 \def\@secfont{\bfseries\Large\section@raggedright\MakeTextUppercase}
 \def\@subsecfont{\bfseries\Large\section@raggedright}
\or %acmcp
\fi
\def\@adddotafter#1{#1\@addpunct{.}}
\def\@addspaceafter#1{#1\@addpunct{\enspace}}
\if@ACM@acmcp
   \setcounter{secnumdepth}{-1}%
\fi
\providecommand*\@dotsep{4.5}
\def\@acmplainbodyfont{\itshape}
\def\@acmplainindent{\parindent}
\def\@acmplainheadfont{\scshape}
\def\@acmplainnotefont{\@empty}
\ifcase\ACM@format@nr
\relax % manuscript
\or % acmsmall
\or % acmlarge
\or % acmtog
\or % sigconf
\or % siggraph
\or % sigplan
  \def\@acmplainbodyfont{\itshape}
  \def\@acmplainindent{\z@}
  \def\@acmplainheadfont{\bfseries}
  \def\@acmplainnotefont{\normalfont}
\or % sigchi
\or % sigchi-a
\or % acmengage
\or % acmcp
\fi
\newtheoremstyle{acmplain}%
  {.5\baselineskip\@plus.2\baselineskip
    \@minus.2\baselineskip}% space above
  {.5\baselineskip\@plus.2\baselineskip
    \@minus.2\baselineskip}% space below
  {\@acmplainbodyfont}% body font
  {\@acmplainindent}% indent amount
  {\@acmplainheadfont}% head font
  {.}% punctuation after head
  {.5em}% spacing after head
  {\thmname{#1}\thmnumber{ #2}\thmnote{ {\@acmplainnotefont(#3)}}}% head spec
\def\@acmdefinitionbodyfont{\normalfont}
\def\@acmdefinitionindent{\parindent}
\def\@acmdefinitionheadfont{\itshape}
\def\@acmdefinitionnotefont{\@empty}
\ifcase\ACM@format@nr
\relax % manuscript
\or % acmsmall
\or % acmlarge
\or % acmtog
\or % sigconf
\or % siggraph
\or % sigplan
  \def\@acmdefinitionbodyfont{\normalfont}
  \def\@acmdefinitionindent{\z@}
  \def\@acmdefinitionheadfont{\bfseries}
  \def\@acmdefinitionnotefont{\normalfont}
\or % sigchi
\or % sigchi-a
\or % acmengage
\or % acmcp
\fi
\newtheoremstyle{acmdefinition}%
  {.5\baselineskip\@plus.2\baselineskip
    \@minus.2\baselineskip}% space above
  {.5\baselineskip\@plus.2\baselineskip
    \@minus.2\baselineskip}% space below
  {\@acmdefinitionbodyfont}% body font
  {\@acmdefinitionindent}% indent amount
  {\@acmdefinitionheadfont}% head font
  {.}% punctuation after head
  {.5em}% spacing after head
  {\thmname{#1}\thmnumber{ #2}\thmnote{ {\@acmdefinitionnotefont(#3)}}}% head spec
\theoremstyle{acmplain}
\AtEndPreamble{%
  \if@ACM@acmthm
  \theoremstyle{acmplain}
  \@ifundefined{theorem}{%
  \newtheorem{theorem}{Theorem}[section]
  }{}
  \@ifundefined{conjecture}{%
  \newtheorem{conjecture}[theorem]{Conjecture}
  }{}
  \@ifundefined{proposition}{%
  \newtheorem{proposition}[theorem]{Proposition}
  }{}
  \@ifundefined{lemma}{%
  \newtheorem{lemma}[theorem]{Lemma}
  }{}
  \@ifundefined{corollary}{%
  \newtheorem{corollary}[theorem]{Corollary}
  }{}
  \theoremstyle{acmdefinition}
  \@ifundefined{example}{%
  \newtheorem{example}[theorem]{Example}
  }{}
  \@ifundefined{definition}{%
  \newtheorem{definition}[theorem]{Definition}
  }{}
  \fi
  \theoremstyle{acmplain}
}
\def\@proofnamefont{\scshape}
\def\@proofindent{\indent}
\ifcase\ACM@format@nr
\relax % manuscript
\or % acmsmall
\or % acmlarge
\or % acmtog
\or % sigconf
\or % siggraph
\or % sigplan
  \def\@proofnamefont{\itshape}
  \def\@proofindent{\noindent}
\or % sigchi
\or % sigchi-a
\or % acmengage
\or % acmcp
\fi
\renewenvironment{proof}[1][\proofname]{\par
  \pushQED{\qed}%
  \normalfont \topsep6\p@\@plus6\p@\relax
  \trivlist
  \item[\@proofindent\hskip\labelsep
        {\@proofnamefont #1\@addpunct{.}}]\ignorespaces
}{%
  \popQED\endtrivlist\@endpefalse
}
\AtEndPreamble{%
  \if@ACM@pbalance
    \global\@ACM@balancefalse
    \ifcase\ACM@format@nr
    \relax % manuscript
       \or % acmsmall
       \or % acmlarge
       \or % acmtog
          \RequirePackage{pbalance}%
       \or % sigconf
          \RequirePackage{pbalance}%
       \or % siggraph
          \RequirePackage{pbalance}%
       \or % sigplan
          \RequirePackage{pbalance}%
       \or % sigchi
          \RequirePackage{pbalance}%
       \or % sigchi-a
       \or % acmengage
          \RequirePackage{pbalance}%
       \or % acmcp
    \fi
  \fi
  \if@ACM@balance
    \ifcase\ACM@format@nr
    \relax % manuscript
         \global\@ACM@balancefalse
       \or % acmsmall
         \global\@ACM@balancefalse
       \or % acmlarge
         \global\@ACM@balancefalse
       \or % acmtog
          \RequirePackage{balance}%
       \or % sigconf
          \RequirePackage{balance}%
       \or % siggraph
          \RequirePackage{balance}%
       \or % sigplan
          \RequirePackage{balance}%
       \or % sigchi
          \RequirePackage{balance}%
       \or % sigchi-a
          \global\@ACM@balancefalse
       \or % acmengage
          \RequirePackage{balance}%
       \or % acmcp
         \global\@ACM@balancefalse
    \fi
  \fi
}
\AtEndDocument{%
  \if@ACM@balance
  \if@twocolumn
  \balance
  \fi\fi}
\newcommand\acksname{Acknowledgments}
\specialcomment{acks}{%
  \begingroup
  \section*{\acksname}
  \phantomsection\addcontentsline{toc}{section}{\acksname}
}{%
  \endgroup
}
\def\grantsponsor#1#2#3{#2}
\newcommand\grantnum[3][]{#3%
  \def\@tempa{#1}\ifx\@tempa\@empty\else\space(\url{#1})\fi}
\AtEndPreamble{%
\if@ACM@screen
  \includecomment{screenonly}
  \excludecomment{printonly}
\else
  \excludecomment{screenonly}
  \includecomment{printonly}
\fi
\if@ACM@anonymous
  \excludecomment{anonsuppress}
  \excludecomment{acks}
\else
  \includecomment{anonsuppress}
\fi}
\newcommand\showeprint[2][arxiv]{%
  \def\@tempa{#1}%
  \ifx\@tempa\@empty\def\@tempa{arxiv}\fi
  \def\@tempb{arxiv}%
  \ifx\@tempa\@tempb\relax
     arXiv:\href{https://arxiv.org/abs/#2}{#2}%
  \else
     \def\@tempb{arXiv}%
     \ifx\@tempa\@tempb\relax
       arXiv:\href{https://arxiv.org/abs/#2}{#2}%
     \else
       #1:#2%
    \fi
  \fi}
\def\theindex{\@restonecoltrue\if@twocolumn\@restonecolfalse\fi
  \columnseprule\z@ \columnsep 35\p@
  \@indextitlestyle
  \let\item\@idxitem
  \parindent\z@  \parskip\z@\@plus.3\p@\relax
  \raggedright
  \hyphenpenalty\@M
  \footnotesize}
\let\@vspace@orig=\@vspace
\let\@vspacer@orig=\@vspacer
\apptocmd{\@vspace}{\ClassWarning{\@classname}{\string\vspace\space should
    only be used to provide space above/below surrounding
    objects}}{}{}
\apptocmd{\@vspacer}{\ClassWarning{\@classname}{\string\vspace\space should
    only be used to provide space above/below surrounding
    objects}}{}{}
\let\@vspace@acm=\@vspace
\let\@vspacer@acm=\@vspacer
\let\ACM@origbaselinestretch\baselinestretch
\AtEndDocument{\ifx\baselinestretch\ACM@origbaselinestretch\else
  \ClassError{\@classname}{An attempt to redefine
    \string\baselinestretch\space detected.  Please do not do this for
    ACM submissions!}\fi}
\normalsize\normalfont\frenchspacing
\endinput
%%
%% End of file `acmart.cls'.
