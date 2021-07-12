#!/bin/bash

rm -rf categories categories.csv tmp headers.csv rules*.txt
xz -d -k headers.csv.xz
cp ../../headers/rules*.txt .
../../headers/classify.sh headers.csv rules1.txt rules2.txt
