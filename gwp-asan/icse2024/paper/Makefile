DOC_PREFIX=gwpasan
BIB_FILES=ref.bib
TEX_FILES=$(shell find ./tex/ -type f -name "*.tex" 2> /dev/null)
SUPPORT_FILES=fig/crashes__svg.pdf
LATEX=pdflatex -file-line-error -halt-on-error
BIBGEN=biber

.PHONY: all
all: pdf

.PHONY: pdf
pdf: $(DOC_PREFIX).pdf

.PHONY: publish
publish: clean pdf
	cp -v $(DOC_PREFIX).pdf pub/$(DOC_PREFIX).pdf

$(DOC_PREFIX).pdf: $(DOC_PREFIX).tex $(TEX_FILES) $(SUPPORT_FILES) $(DOC_PREFIX).bbl
	@echo "======================================================"
	$(LATEX) $(DOC_PREFIX).tex

$(DOC_PREFIX).bbl: $(BIB_FILES)
	@echo "======================================================"
	$(LATEX) $(DOC_PREFIX).tex
	@echo "------------------------------------------------------"
	$(BIBGEN) $(DOC_PREFIX)
	@echo "------------------------------------------------------"
	$(LATEX) $(DOC_PREFIX).tex

%__svg.pdf: %.svg
	@echo "======================================================"
	inkscape --export-pdf=$@ $<

.PHONY: clean
clean:
	$(RM) $(DOC_PREFIX).pdf
	$(RM) $(DOC_PREFIX).out
	$(RM) $(DOC_PREFIX).log
	$(RM) $(DOC_PREFIX).ps
	$(RM) $(DOC_PREFIX).dvi
	$(RM) $(DOC_PREFIX).aux
	$(RM) $(DOC_PREFIX).bbl
	$(RM) $(DOC_PREFIX).blg
	$(RM) $(DOC_PREFIX).toc
	$(RM) $(DOC_PREFIX).lof
	$(RM) $(DOC_PREFIX).lol
	$(RM) $(DOC_PREFIX).lot
	$(RM) $(DOC_PREFIX).nav
	$(RM) $(DOC_PREFIX).snm
	$(RM) $(DOC_PREFIX).bcf
	$(RM) $(DOC_PREFIX).run.xml

.PHONY: install-deps
install-deps:
	sudo apt install \
		texlive-latex-base \
		texlive-latex-extra \
		texlive-latex-recommended \
		texlive-fonts-extra \
		texlive-bibtex-extra \
		biber \
		inkscape

.PHONY:
archive: $(DOC_PREFIX).tex $(TEX_FILES) $(SUPPORT_FILES) $(DOC_PREFIX).bbl
	tar -cvzf $(DOC_PREFIX).tar.gz $^
