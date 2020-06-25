DEBUG = YES
CC = gcc

CFLAGS = -W
LFLAGS = -lpcap

EXEC = bin/program
DIRECTORIES = src include obj bin

# Debug permets d'utiliser gdb
ifeq ($(DEBUG), YES)
		override CFLAGS := -g $(CFLAGS)
endif

# Les wildcards indiquent où sont les fichiers
HEADERS = $(wildcard include/*.h)
SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:src/%.c=obj/%.o)

# les .PHONY représentent toutes les règles qu'il ne faut pas confondre avec des fichiers.
# -> si jamais un fichier "clean" existe, make l'ignorera si jamais on fait "make clean".
.PHONY : all clean dir archive

# $@ est le nom du fichier concerné par la règle
# $< le nom du premier prérequis

all : dir $(EXEC)
ifeq ($(DEBUG), YES)
	@echo "==== Generated in debug mode ===="
else
	@echo "==== Generated in release mode ===="
endif

$(EXEC) : $(OBJECTS) $(HEADERS)
	@echo "\n==== Linking ===="
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LFLAGS)
	@echo ""

obj/%.o : src/%.c
	@echo "\n---- Rule " $@ "----"
	$(CC) $(CFLAGS) -c $<
	@mv *.o obj

# clean supprime les .o
clean :
	@echo "==== Cleaning ===="
	rm obj/*.o $(EXEC)

# create directories.
dir :
	@for dir in $(DIRECTORIES); do \
		exists=$$([ -d $$dir ]; echo $$?); \
		if [ "$$exists" -eq "1" ]; then \
				mkdir $$dir; \
		fi \
	done

archive :
	@echo "==== Archiving ===="
	zip andreas_guillot.zip -r src/ include/
