#!/bin/bash

CLASSIFICATION="categories"
CLASSIFICATION_CSV="$CLASSIFICATION.csv"
TMP="tmp"

# clear old classification
# rm -fr "$CLASSIFICATION" "$CLASSIFICATION_CSV" "$TMP"

HEADER="$1"
shift
if [ -z "$HEADER" ]; then
    echo 'first argument (header file) missing'
    exit 1
fi
if [ ! -f "$HEADER" ]; then
    echo "$HEADER is not a regular file"
    exit 1
fi

if [ -e "$CLASSIFICATION" ]; then
    echo "$CLASSIFICATION already exists"
    exit 1
fi
if [ -e "$CLASSIFICATION_CSV" ]; then
    echo "$CLASSIFICATION_CSV already exists"
    exit 1
fi
if [ -e "TMP" ]; then
    echo "$TMP already exists"
    exit 1
fi

mkdir "$CLASSIFICATION"
if [ ! -d "$CLASSIFICATION" ]; then
    echo "Cannot create $CLASSIFICATION"
    exit 1
fi
touch "$CLASSIFICATION_CSV"
if [ ! -f "$CLASSIFICATION_CSV" ]; then
    echo "Cannot create $CLASSIFICATION_CSV"
    exit 1
fi
mkdir "$TMP"
if [ ! -d "$TMP" ]; then
    echo "Cannot create $TMP"
    exit 1
fi

function filter {
    pattern_file="$1"
    headers="$TMP/$2"
    rest="$TMP/$3"
    while read -r line; do
        read -r pattern category exclude_pattern <<< "${line%%#*}"
	if [ -z "$category" ]; then
	    echo "'$line' skipped"
	    continue
	fi
	if [ -z "$exclude_pattern" ]; then
            egrep -i "$pattern" "$headers" >> "$CLASSIFICATION/$category.csv"
	else
            egrep -i "$pattern" "$headers" | egrep -i -v "$exclude_pattern" >> "$CLASSIFICATION/$category.csv"
	fi
    done < "$pattern_file"
    join -t';' -v 1 -j 1 "$headers" <(sort -u "$CLASSIFICATION"/*) > "$rest"
}


# Categorize the headers in $HEADER using the pattern files on the command line

NEXT=0
sort -u "$HEADER" | sed '/^$/d' > "$TMP/$NEXT"
for pattern_file; do
    LAST=$NEXT
    NEXT=$((LAST+1))
    filter "$pattern_file" "$LAST" "$NEXT"
done

for csv in "$CLASSIFICATION"/*; do
    category=${csv##*/}
    category=${category%.csv}
    sort -u "$csv" | sed "s/\$/;$category/" >> "$CLASSIFICATION_CSV"
done

